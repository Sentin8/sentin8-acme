// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Post-quantum CA hierarchy (PQCA-2, acme DESIGN "CA families per mode").
//!
//! The PQ cert families (`hybrid`, `exclusive`) mint a post-quantum
//! *signature* chain:
//!
//! - **Root**: SLH-DSA-SHA2-128s (the security anchor - small, slow, and
//!   minted once per CA lifetime; stateless hash-based, the conservative
//!   choice for the one cert the whole platform trusts).
//! - **Intermediate + leaves**: ML-DSA-65 (fast enough for per-tenant
//!   minting; the same family the TLS handshake carries, so a leaf's
//!   handshake signature and its cert signature come from one family).
//!
//! Certificates are built with the RustCrypto `x509-cert` builder - `rcgen`
//! cannot carry PQ signature algorithms (its `SignatureAlgorithm` has private
//! fields pinned to ring/aws-lc backers). The builder accepts any signer
//! implementing `Signer + Keypair + SignatureAlgorithmIdentifier`; both
//! `ml-dsa` and `slh-dsa` provide those, so the mint is pure Rust with no
//! OpenSSL dependency.
//!
//! The minted PEMs land in the per-mode data dir (PQCA-1):
//! `{SENTIN8_ACME_DATA_DIR}/{pq_mode}/ca/...`. Consumers that must parse
//! these certs need PQ awareness (OpenSSL 3.5+, or the platform's own
//! verifier) - the split-CA posture documents which consumers stay on the
//! `classical` chain until then.

use std::path::Path;

use der::Encode;
use slh_dsa::signature::Keypair as _;
use ml_dsa::Generate;
use slh_dsa::ParameterSet as _;
use std::str::FromStr as _;
use x509_cert::builder::{Builder, CertificateBuilder, profile::cabf};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use crate::config::AcmeConfig;

/// The SLH-DSA-SHA2-128s root key pair (minted once, loaded thereafter).
pub type SlhRootKey = slh_dsa::SigningKey<slh_dsa::Sha2_128s>;
/// The ML-DSA-65 intermediate key pair.
pub type MlDsaIntKey = ml_dsa::SigningKey<ml_dsa::MlDsa65>;

/// The minted PQ hierarchy: PEM bytes + the in-memory signing keys.
///
/// The root key signs nothing at runtime (only the intermediate's mint);
/// the intermediate signs every leaf. Both are loaded from/persisted to
/// the per-mode `ca/` directory.
pub struct PqCaHierarchy {
    /// Root CA cert PEM (self-signed, SLH-DSA-SHA2-128s).
    pub root_cert_pem: Vec<u8>,
    /// Intermediate CA cert PEM (signed by the root, ML-DSA-65).
    pub intermediate_cert_pem: Vec<u8>,
    /// The intermediate signing key (leaf mints).
    pub intermediate_key: MlDsaIntKey,
}

impl PqCaHierarchy {
    /// Load the PQ hierarchy from `ca/` when present, else mint it.
    ///
    /// Mirrors [`crate::ca::CaHierarchy::ensure`] (load-if-exists, else
    /// generate) but over the PQ material: the root + intermediate certs
    /// and the intermediate key. The root key is only needed at
    /// intermediate-mint time - it stays on disk (0600) and is never kept
    /// in memory after the mint.
    pub fn ensure(config: &AcmeConfig) -> Result<Self, String> {
        let root_cert = std::fs::read(config.root_ca_cert_path());
        let int_cert = std::fs::read(config.intermediate_ca_cert_path());
        let int_key = std::fs::read(config.intermediate_ca_key_path());
        match (root_cert, int_cert, int_key) {
            (Ok(root_pem), Ok(int_pem), Ok(key_pem)) => {
                let intermediate_key = parse_ml_dsa_pem(&key_pem)
                    .map_err(|e| format!("load ML-DSA-65 intermediate key: {e}"))?;
                tracing::info!("Loading existing PQ CA hierarchy (SLH-DSA root / ML-DSA-65)");
                Ok(Self {
                    root_cert_pem: root_pem,
                    intermediate_cert_pem: int_pem,
                    intermediate_key,
                })
            }
            _ => {
                tracing::info!("Generating new PQ CA hierarchy (SLH-DSA-SHA2-128s root / ML-DSA-65)");
                Self::generate(config)
            }
        }
    }

    fn generate(config: &AcmeConfig) -> Result<Self, String> {
        let ca_dir = config.ca_dir();
        std::fs::create_dir_all(&ca_dir).map_err(|e| format!("create {}: {e}", ca_dir.display()))?;

        // ── Root: SLH-DSA-SHA2-128s self-signed ──
        let root_key = generate_slh_root_key();
        let root_cert = build_root_cert(&root_key, config.root_ca_days)
            .map_err(|e| format!("build PQ root cert: {e}"))?;
        let root_pem = pem_encode(&root_cert.to_der().map_err(|e| format!("root DER: {e}"))?);

        // Persist the root (key 0600 - the anchor's private half).
        std::fs::write(config.root_ca_cert_path(), &root_pem)
            .map_err(|e| format!("write root cert: {e}"))?;
        std::fs::write(config.root_ca_key_path(), serialize_slh_pem(&root_key)?)
            .map_err(|e| format!("write root key: {e}"))?;
        set_key_perms(&config.root_ca_key_path())?;

        // ── Intermediate: ML-DSA-65, signed by the root ──
        let intermediate_key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate();
        let intermediate_cert = build_intermediate_cert(
            &intermediate_key,
            &root_cert,
            &root_key,
            config.intermediate_ca_days,
        )
        .map_err(|e| format!("build PQ intermediate cert: {e}"))?;
        let int_pem = pem_encode(&intermediate_cert.to_der().map_err(|e| format!("int DER: {e}"))?);

        std::fs::write(config.intermediate_ca_cert_path(), &int_pem)
            .map_err(|e| format!("write intermediate cert: {e}"))?;
        std::fs::write(
            config.intermediate_ca_key_path(),
            serialize_ml_dsa_pem(&intermediate_key)?,
        )
        .map_err(|e| format!("write intermediate key: {e}"))?;
        set_key_perms(&config.intermediate_ca_key_path())?;

        Ok(Self {
            root_cert_pem: root_pem,
            intermediate_cert_pem: int_pem,
            intermediate_key,
        })
    }

    /// Mint an ML-DSA-65 server leaf (CN + SANs), signed by the
    /// intermediate. Returns `(chain_pem = leaf + intermediate, key_pem)`.
    pub fn sign_leaf(
        &self,
        common_name: &str,
        san_dns_names: &[String],
        days: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let leaf_key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::generate();
        let leaf_cert = build_leaf_cert(
            &leaf_key,
            common_name,
            san_dns_names,
            &self.intermediate_key,
            &parse_cert_der(&self.intermediate_cert_pem)
                .map_err(|e| format!("parse intermediate cert: {e}"))?,
            days,
        )
        .map_err(|e| format!("sign PQ leaf: {e}"))?;

        let leaf_pem = pem_encode(&leaf_cert.to_der().map_err(|e| format!("leaf DER: {e}"))?);
        // Chain = leaf + intermediate (the verifier holds the root).
        let mut chain = leaf_pem.clone();
        chain.extend_from_slice(&self.intermediate_cert_pem);
        let key_pem = serialize_ml_dsa_pem(&leaf_key)?;
        Ok((chain, key_pem))
    }
}

/// Build the self-signed SLH-DSA root certificate.
fn build_root_cert(
    root_key: &SlhRootKey,
    days: u64,
) -> Result<x509_cert::Certificate, String> {
    let subject = ca_name("Sentin8 Local Development PQ Root CA")?;
    let profile = cabf::Root::new(false, subject).map_err(|e| format!("root profile: {e}"))?;
    let spki = spki_slh_dsa(&root_key.verifying_key())?;
    let serial = random_serial()?;
    let validity = validity_from_days(days, "root")?;
    let builder = CertificateBuilder::new(profile, serial, validity, spki)
        .map_err(|e| format!("root builder: {e}"))?;
    builder
        .build::<_, slh_dsa::Signature<slh_dsa::Sha2_128s>>(root_key)
        .map_err(|e| format!("root self-sign: {e}"))
}

/// Build the ML-DSA-65 intermediate, signed by the SLH-DSA root.
fn build_intermediate_cert(
    int_key: &MlDsaIntKey,
    root_cert: &x509_cert::Certificate,
    root_key: &SlhRootKey,
    days: u64,
) -> Result<x509_cert::Certificate, String> {
    use ml_dsa::Keypair as _;
    let subject = ca_name("Sentin8 Local Development PQ Intermediate CA")?;
    let issuer = root_cert.tbs_certificate().subject().clone();
    let profile = cabf::tls::Subordinate {
        issuer,
        subject,
        path_len_constraint: Some(0),
        emits_ocsp_response: false,
        client_auth: true,
    };
    let spki = spki_ml_dsa(&int_key.verifying_key())?;
    let serial = random_serial()?;
    let validity = validity_from_days(days, "intermediate")?;
    let builder = CertificateBuilder::new(profile, serial, validity, spki)
        .map_err(|e| format!("intermediate builder: {e}"))?;
    builder
        .build::<_, slh_dsa::Signature<slh_dsa::Sha2_128s>>(root_key)
        .map_err(|e| format!("intermediate sign: {e}"))
}

/// Build an ML-DSA-65 server leaf, signed by the ML-DSA-65 intermediate.
fn build_leaf_cert(
    leaf_key: &MlDsaIntKey,
    common_name: &str,
    san_dns_names: &[String],
    issuer_key: &MlDsaIntKey,
    issuer_cert: &x509_cert::Certificate,
    days: u64,
) -> Result<x509_cert::Certificate, String> {
    use ml_dsa::Keypair as _;
    let subject = leaf_name(common_name)?;
    let issuer = issuer_cert.tbs_certificate().subject().clone();
    let profile = cabf::tls::Subordinate {
        issuer,
        subject,
        path_len_constraint: None,
        emits_ocsp_response: false,
        client_auth: true,
    };
    let spki = spki_ml_dsa(&leaf_key.verifying_key())?;
    let serial = random_serial()?;
    let validity = validity_from_days(days, "leaf")?;
    let mut builder = CertificateBuilder::new(profile, serial, validity, spki)
        .map_err(|e| format!("leaf builder: {e}"))?;
    // SANs: the leaf covers the tenant hostname(s). One extension carries
    // every DNS name (the RFC form) - hand-built: the pkix ToExtension
    // wiring for SubjectAltName is feature-gated in this x509-cert
    // version, so the DER is encoded here (GeneralNames ::= SEQUENCE OF
    // GeneralName; [2] = dNSName IA5String).
    if !san_dns_names.is_empty() {
        let san_der;
        let mut general_names: Vec<x509_cert::ext::pkix::name::GeneralName> = Vec::new();
        for name in san_dns_names {
            let ia5 = der::asn1::Ia5String::new(name.as_bytes())
                .map_err(|e| format!("SAN ia5 {name}: {e}"))?;
            general_names.push(x509_cert::ext::pkix::name::GeneralName::DnsName(ia5));
        }
        san_der = general_names.to_der().map_err(|e| format!("SAN DER: {e}"))?;
        let ext = x509_cert::ext::Extension {
            extn_id: <x509_cert::ext::pkix::SubjectAltName as const_oid::AssociatedOid>::OID,
            critical: false.into(),
            extn_value: der::asn1::OctetString::new(san_der)
                .map_err(|e| format!("SAN octet: {e}"))?,
        };
        builder
            .add_extension(ext)
            .map_err(|e| format!("leaf SAN: {e}"))?;
    }
    builder
        .build::<_, ml_dsa::Signature<ml_dsa::MlDsa65>>(issuer_key)
        .map_err(|e| format!("leaf sign: {e}"))
}

// ── helpers ──────────────────────────────────────────────────────────────

/// A validity window starting now and lasting `days` days.
///
/// Built from `Time::try_from(SystemTime)` so the mint needs no
/// `x509-cert` std feature (the crate's `Validity::from_now` is gated).
fn validity_from_days(days: u64, what: &str) -> Result<Validity, String> {
    let now = std::time::SystemTime::now();
    let then = now
        .checked_add(std::time::Duration::from_secs(days * 86400))
        .ok_or_else(|| format!("{what} validity overflow"))?;
    let not_before: der::DateTime = now
        .try_into()
        .map_err(|e: der::Error| format!("{what} not_before: {e}"))?;
    let not_after: der::DateTime = then
        .try_into()
        .map_err(|e: der::Error| format!("{what} not_after: {e}"))?;
    Ok(Validity::new(
        x509_cert::time::Time::from(not_before),
        x509_cert::time::Time::from(not_after),
    ))
}

/// A CABF-conformant CA name (C/O/CN are all required by the Root profile).
fn ca_name(cn: &str) -> Result<Name, String> {
    Name::from_str(&format!("CN={cn},O=Sentin8,C=US")).map_err(|e| format!("CA name: {e}"))
}

/// A leaf subject name (no CA-name constraints on end-entity certs).
fn leaf_name(cn: &str) -> Result<Name, String> {
    Name::from_str(&format!("CN={cn}")).map_err(|e| format!("leaf name: {e}"))
}

/// SPKI for an ML-DSA-65 verifying key (`encode()` = the raw public key).
fn spki_ml_dsa(
    vk: &ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
) -> Result<x509_cert::SubjectPublicKeyInfo, String> {
    spki_from_raw(vk.encode().as_ref(), ml_dsa_oid())
}

/// SPKI for an SLH-DSA-SHA2-128s verifying key (`to_bytes()`).
fn spki_slh_dsa(
    vk: &slh_dsa::VerifyingKey<slh_dsa::Sha2_128s>,
) -> Result<x509_cert::SubjectPublicKeyInfo, String> {
    spki_from_raw(&vk.to_bytes(), slh_dsa_oid())
}

/// Wrap a raw public key in an SPKI (the FIPS 204/205 algorithm OID +
/// the key bytes as the subjectPublicKey BIT STRING). Hand-rolled: the
/// two PQ crates implement different-generation `EncodePublicKey`
/// traits (pkcs8 0.10 vs 0.11), so one generic cannot serve both.
fn spki_from_raw(
    raw: &[u8],
    oid: der::asn1::ObjectIdentifier,
) -> Result<x509_cert::SubjectPublicKeyInfo, String> {
    let params = x509_cert::spki::AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    };
    let bit = der::asn1::BitString::new(0, raw.to_vec())
        .map_err(|e| format!("SPKI bitstring: {e}"))?;
    Ok(x509_cert::spki::SubjectPublicKeyInfoOwned {
        algorithm: params,
        subject_public_key: bit,
    })
}

/// The ML-DSA-65 algorithm OID (FIPS 204, 2.16.840.1.101.3.4.3.18).
fn ml_dsa_oid() -> der::asn1::ObjectIdentifier {
    <ml_dsa::MlDsa65 as x509_cert::spki::AssociatedAlgorithmIdentifier>::ALGORITHM_IDENTIFIER.oid
}

/// The SLH-DSA-SHA2-128s algorithm OID (FIPS 205).
fn slh_dsa_oid() -> der::asn1::ObjectIdentifier {
    slh_dsa::Sha2_128s::ALGORITHM_OID
}

/// A random positive serial number (the builder takes `SerialNumber`).
fn random_serial() -> Result<SerialNumber, String> {
    use rand::RngCore as _;
    let mut buf = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let serial = u64::from_be_bytes(buf) & 0x7fff_ffff_ffff_ffff; // positive
    Ok(SerialNumber::from(serial))
}

/// Minimal PEM armor (CERTIFICATE) for a certificate DER.
fn pem_encode(der: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(b64.len() + 64);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out.into_bytes()
}

/// Serialize an ML-DSA-65 key as a PKCS#8 PEM.
fn serialize_ml_dsa_pem(key: &MlDsaIntKey) -> Result<Vec<u8>, String> {
    use pkcs8::EncodePrivateKey as _;
    let pem = key
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .map_err(|e| format!("ML-DSA PKCS#8 PEM: {e}"))?;
    Ok(pem.as_str().as_bytes().to_vec())
}

/// Serialize the SLH-DSA root key as raw PEM (the crate has no PKCS#8
/// PEM; `to_bytes()` is the full key material).
fn serialize_slh_pem(key: &SlhRootKey) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    let bytes = key.to_bytes();
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut out = String::new();
    out.push_str("-----BEGIN SLH-DSA-SHA2-128S PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END SLH-DSA-SHA2-128S PRIVATE KEY-----\n");
    Ok(out.into_bytes())
}

/// Parse an ML-DSA-65 PKCS#8 PEM key.
fn parse_ml_dsa_pem(pem: &[u8]) -> Result<MlDsaIntKey, String> {
    use pkcs8::DecodePrivateKey as _;
    let text = std::str::from_utf8(pem).map_err(|e| format!("key PEM utf8: {e}"))?;
    ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_pkcs8_pem(text)
        .map_err(|e| format!("ML-DSA PKCS#8 parse: {e}"))
}

/// Parse a certificate PEM to DER (for the intermediate-at-leaf-signing).
fn parse_cert_der(pem: &[u8]) -> Result<x509_cert::Certificate, String> {
    use der::Decode as _;
    let text = std::str::from_utf8(pem).map_err(|e| format!("cert PEM utf8: {e}"))?;
    let stripped = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>();
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(stripped.trim())
        .map_err(|e| format!("cert base64: {e}"))?;
    x509_cert::certificate::Certificate::from_der(&der).map_err(|e| format!("cert DER: {e}"))
}

/// Generate the SLH-DSA-SHA2-128s root key (OS entropy). The crate's
/// `SigningKey::new` wants a `rand_core` 0.10 RNG (the crypto-common
/// re-export the PQ crates agree on); the classical `rand 0.8` OsRng is
/// a different trait generation.
fn generate_slh_root_key() -> SlhRootKey {
    // getrandom 0.3 exposes imperative fill(); wrap it in the minimal
    // rand_core 0.10 CryptoRng the PQ crates require (Error = Infallible:
    // an OS-RNG failure at key-mint time is unrecoverable either way,
    // so the adapter panics - the same contract the classical KeyPair
    // generation paths carry).
    struct SysRngAdapter;
    impl rand_core::TryRng for SysRngAdapter {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut b = [0u8; 4];
            getrandom::fill(&mut b).expect("OS entropy (u32)");
            Ok(u32::from_le_bytes(b))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut b = [0u8; 8];
            getrandom::fill(&mut b).expect("OS entropy (u64)");
            Ok(u64::from_le_bytes(b))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            getrandom::fill(dst).expect("OS entropy (fill)");
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for SysRngAdapter {}
    let mut rng = SysRngAdapter;
    SlhRootKey::new(&mut rng)
}

/// 0600 key perms (the CA private halves).
fn set_key_perms(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| format!("chmod {}: {e}", path.display()))
}
