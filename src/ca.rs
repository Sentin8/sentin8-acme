// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! CA management - Root CA and Intermediate CA generation, signing.
//!
//! A two-tier CA hierarchy: Root CA (self-signed) → Intermediate CA
//! (signed by Root) → Leaf certificates (signed by Intermediate).

use chrono::{DateTime, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::config::AcmeConfig;

/// The OU every CA subject names the issuing service with (PQCA-3) -
/// carried by the intermediate only; the CABF root profile admits no OU
/// on the root subject (BR 7.1.2.10.2).
pub const CA_SUBJECT_OU: &str = "Sentin8:ACME";

/// Mode-derived CA subject common names (PQCA-3).
///
/// Returns `(root_cn, intermediate_cn)` named for the mode of the STORE
/// BEING MINTED - resolved from `config.data_dir`'s mode segment, NOT the
/// process env: `ensure_mode` (the `--ensure-ca` multi-mode path) pins
/// the data dir to a named mode while the env may hold another, and a
/// hierarchy must be named for the mode it lives under (the PQCA-3 rule
/// - `ensure --modes=classical` under an exclusive env mints a
/// `Sentin8 Classical Root CA`, never an Exclusive-named one). The
/// ACTIVE-mode callers (`CaFamily::ensure`, the runtime boot) pass a
/// config whose data dir IS the active mode dir (PQCA-1), so the same
/// derivation serves both.
///
/// The full subjects are:
/// - root: `CN={root_cn}, O=Sentin8, C=CA` - NO OU (CABF BR 7.1.2.10.2:
///   the root CA subject admits no organizationalUnitName; the
///   `x509-cert` builder's `cabf::Root` profile enforces it).
/// - intermediate: `CN={intermediate_cn}, OU=Sentin8:ACME, O=Sentin8,
///   C=CA` - the OU names the issuing service (admitted on non-root CA
///   subjects); the country is Canada (`C=CA`, ISO 3166-1).
pub fn ca_subject_common_names_for(config: &AcmeConfig) -> (String, String) {
    let mode = config
        .data_dir
        .file_name()
        .and_then(|m| m.to_str())
        .unwrap_or("exclusive");
    let mode_word = match mode {
        "classical" => "Classical",
        "hybrid" => "Hybrid",
        _ => "Exclusive",
    };
    (
        format!("Sentin8 {mode_word} Root CA"),
        format!("Sentin8 {mode_word} Intermediate CA"),
    )
}

/// [`ca_subject_common_names_for`] over the ACTIVE-mode config - the
/// display-name helper (the admin UI cards, tests pinning the env).
pub fn ca_subject_common_names() -> (String, String) {
    // An active-mode config: the same derivation AcmeConfig::from_env
    // applies (PQCA-1) - a throwaway config object built purely to
    // carry the active data dir.
    let cfg = AcmeConfig {
        data_dir: std::path::PathBuf::from(sentin8::config::acme_data_dir_mode(
            &std::env::var("SENTIN8_ACME_DATA_DIR")
                .unwrap_or_else(|_| sentin8::config::tls_dir()),
        )),
        ..crate::infra_tls::offline_config()
    };
    ca_subject_common_names_for(&cfg)
}

/// The ACTIVE mode's CA family - the ONE dispatch every mint-or-load
/// site goes through (CAMINT-1, PQCA-2). `classical` mints through the
/// ECDSA `CaHierarchy` (rcgen); `hybrid`/`exclusive` through the PQ
/// `PqCaHierarchy` (SLH-DSA root / ML-DSA-65 intermediate + leafs). A
/// mint path that hardcodes a hierarchy type is a defect: a posture
/// flip (`SENTIN8_TLS_PQ_MODE`) would mint leafs the trust store cannot
/// chain.
///
/// The family is resolved ONCE per call from `sentin8::config::pq_mode()`
/// - the same knob that scopes the per-mode data dir (PQCA-1) - so the
/// hierarchy and its store can never disagree.
pub enum CaFamily {
    /// The ECDSA P-256 chain (rcgen).
    Classical(CaHierarchy),
    /// The SLH-DSA root / ML-DSA-65 chain.
    Pq(crate::pq_ca::PqCaHierarchy),
}

impl CaFamily {
    /// Resolve + ensure the ACTIVE mode's family (load-if-exists, else
    /// mint). Errors verbatim from the underlying hierarchy ensure.
    pub fn ensure(config: &AcmeConfig) -> Result<Self, String> {
        match sentin8::config::pq_mode().as_str() {
            "classical" => Ok(Self::Classical(CaHierarchy::ensure(config)?)),
            _ => Ok(Self::Pq(crate::pq_ca::PqCaHierarchy::ensure(config)?)),
        }
    }

    /// Ensure a NAMED mode's family - the `--ensure-ca` multi-mode path
    /// (CAMINT-1). The mode pins the data dir (PQCA-1), so each family
    /// addresses its own store; `CaFamily::ensure` (the active-mode path)
    /// is this over `pq_mode()`.
    pub fn ensure_mode(config: &AcmeConfig, mode: &str) -> Result<Self, String> {
        // A mode-pinned config: the same offline fields, data dir scoped
        // to the requested mode (the derivation `offline_config` applies,
        // with the mode word taken from the caller).
        let mut scoped = config.clone();
        let base = std::env::var("SENTIN8_ACME_DATA_DIR")
            .unwrap_or_else(|_| sentin8::config::tls_dir());
        scoped.data_dir = std::path::PathBuf::from(format!(
            "{}/{mode}",
            base.trim_end_matches('/')
        ));
        match mode {
            "classical" => Ok(Self::Classical(CaHierarchy::ensure(&scoped)?)),
            "hybrid" | "exclusive" => Ok(Self::Pq(crate::pq_ca::PqCaHierarchy::ensure(&scoped)?)),
            other => Err(format!(
                "unknown PQ mode '{other}' (expected classical, hybrid, or exclusive)"
            )),
        }
    }

    /// Sign a server leaf (CN + SANs) with the family's chain.
    /// Returns the full chain PEM (leaf + intermediate [+ root for the
    /// classical family - `CaHierarchy::sign_leaf` includes it]).
    pub fn sign_leaf(
        &self,
        common_name: &str,
        san_dns_names: &[String],
        days: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        match self {
            Self::Classical(ca) => ca.sign_leaf(common_name, san_dns_names, days),
            Self::Pq(ca) => ca.sign_leaf(common_name, san_dns_names, days),
        }
    }

    /// Sign a client-auth (mTLS workload) leaf with the family's chain.
    pub fn sign_client_leaf(
        &self,
        common_name: &str,
        days: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        match self {
            Self::Classical(ca) => ca.sign_client_leaf(common_name, days),
            Self::Pq(ca) => ca.sign_client_leaf(common_name, days),
        }
    }

    /// The Root CA certificate PEM (on-disk bytes) - the runtime
    /// `GET /v1/ca/root.crt` surface, delegated per family.
    pub fn root_ca_pem(&self) -> String {
        match self {
            Self::Classical(ca) => ca.root_ca_pem(),
            Self::Pq(ca) => String::from_utf8_lossy(&ca.root_cert_pem).into_owned(),
        }
    }

    /// The Intermediate CA certificate PEM (on-disk bytes, signed by
    /// the root) - the runtime `GET /v1/ca/intermediate.crt` surface,
    /// delegated per family.
    pub fn intermediate_ca_pem(&self) -> String {
        match self {
            Self::Classical(ca) => ca.intermediate_ca_pem(),
            Self::Pq(ca) => {
                String::from_utf8_lossy(&ca.intermediate_cert_pem).into_owned()
            }
        }
    }

    /// SHA-256 fingerprint of the root CA PEM - the admin UI display.
    pub fn root_ca_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.root_ca_pem().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// The public CA chain (root + intermediate) for the family - the
    /// `{secrets}/acme-ca` copy verifiers hold. NOTE: reads the
    /// CONFIG's data dir - callers that resolve a NAMED mode's family
    /// (`CaFamily::ensure_mode`, the `--ensure-ca` multi-mode path)
    /// must scope the config to that mode first or use
    /// [`Self::ca_chain_pem_for_config`] with the scoped config.
    pub fn ca_chain_pem(&self, config: &AcmeConfig) -> Result<Vec<u8>, String> {
        let mut chain = std::fs::read(config.root_ca_cert_path())
            .map_err(|e| format!("read root CA: {e}"))?;
        let int = std::fs::read(config.intermediate_ca_cert_path())
            .map_err(|e| format!("read intermediate CA: {e}"))?;
        chain.extend_from_slice(&int);
        Ok(chain)
    }

    /// [`Self::ca_chain_pem`] - the alias making the scoping contract
    /// explicit for callers holding a mode-scoped config (the infra
    /// mint passes its classical-scoped config).
    pub fn ca_chain_pem_for_config(&self, config: &AcmeConfig) -> Result<Vec<u8>, String> {
        self.ca_chain_pem(config)
    }
}

/// Whether the leaf on disk belongs to the ACTIVE signature family -
/// the reuse predicate's family check (CAMINT-1). A still-valid leaf of
/// the WRONG family (ECDSA leaf under `exclusive`, ML-DSA leaf under
/// `classical`) must be re-minted, never served: the trust store holds
/// the ACTIVE family's chain and cannot chain the other.
pub fn leaf_matches_family(cert_path: &Path) -> bool {
    leaf_matches_family_mode(cert_path, &sentin8::config::pq_mode())
}

/// [`leaf_matches_family`] - but against a NAMED mode (the `--ensure-ca`
/// multi-mode path and tests pin the dir to a named mode while the
/// process env holds another, so the reuse predicate must check
/// exactly that family).
pub fn leaf_matches_family_mode(cert_path: &Path, mode: &str) -> bool {
    let Ok(pem) = std::fs::read_to_string(cert_path) else {
        return false;
    };
    let Some(cert) = parse_leaf_cert(pem.as_bytes()) else {
        // Unparsable = not provably the right family = re-mint (fail
        // toward mint, the same discipline as `leaf_is_valid`).
        return false;
    };
    // The SIGNATURE algorithm is the family marker: the classical chain
    // (rcgen) signs with ecdsa-with-SHA256, the PQ chain with ML-DSA-65.
    // The SPKI (public key) algorithm is NOT the marker - both chains
    // may present classical keys, and an ECDSA leaf signed by the PQ
    // family is still PQ-family (its verifier is the PQ chain).
    let sig_alg = cert.signature_algorithm().oid;
    let want_pq = mode != "classical";
    let is_pq = sig_alg == ml_dsa_oid();
    is_pq == want_pq
}

/// The leaf's ISSUER DN is the family marker - `leaf_matches_family_mode`
pub(crate) fn leaf_issuer_dn_matches_intermediate(
    leaf_pem: &[u8],
    intermediate_pem: &[u8],
) -> bool {
    let Some(leaf) = parse_leaf_cert(leaf_pem) else {
        return false;
    };
    let Some(intermediate) = parse_leaf_cert(intermediate_pem) else {
        return false;
    };
    leaf.tbs_certificate().issuer() == intermediate.tbs_certificate().subject()
}

/// Parse a PEM leaf to an x509-cert `Certificate` (first block only) - a
/// minimal DER walk shared by the family check.
pub fn parse_leaf_cert(pem: &[u8]) -> Option<x509_cert::certificate::Certificate> {
    use base64::Engine as _;
    use der::Decode as _;
    let text = std::str::from_utf8(pem).ok()?;
    let mut b64 = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            inside = true;
            continue;
        }
        if line.contains("END CERTIFICATE") {
            break;
        }
        if inside {
            b64.push_str(line.trim());
        }
    }
    let der = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
    x509_cert::certificate::Certificate::from_der(&der).ok()
}

/// The ML-DSA-65 algorithm OID - delegated to the PQ chain's helper so
/// the two can never drift apart.
fn ml_dsa_oid() -> der::asn1::ObjectIdentifier {
    <ml_dsa::MlDsa65 as x509_cert::spki::AssociatedAlgorithmIdentifier>::ALGORITHM_IDENTIFIER.oid
}

/// Push the country DN entry (`C=CA`, Canada) as a PrintableString -
/// RFC 5280 §B.1 encodes countryName as PrintableString, and CABF
/// consumers (and the `x509-cert` test parser) expect that tag for C;
/// rcgen's default `Into<DnValue>` path would emit UTF8String.
fn push_country_ca(dn: &mut DistinguishedName) {
    let country = rcgen::PrintableString::try_from("CA")
        .expect("'CA' is a valid PrintableString");
    dn.push(DnType::CountryName, rcgen::DnValue::PrintableString(country));
}

/// Decode an X.501 attribute value (`Any`) to its TYPED rcgen `DnValue`
/// so the string encoding survives the reconstruction byte-for-byte (the
/// webpki issuer/subject DN equality - see `reconstruct_ca_cert_from_pem`).
fn atv_dn_value(value: &der::asn1::Any) -> Result<rcgen::DnValue, String> {
    use der::Tagged as _;
    match value.tag() {
        der::Tag::PrintableString => {
            let s = der::asn1::PrintableStringRef::try_from(value)
                .map_err(|e| format!("CA subject PrintableString: {e}"))?;
            let printable = rcgen::PrintableString::try_from(s.as_str())
                .map_err(|e| format!("CA subject PrintableString content: {e}"))?;
            Ok(rcgen::DnValue::PrintableString(printable))
        }
        der::Tag::Utf8String => Ok(rcgen::DnValue::Utf8String(
            der::asn1::Utf8StringRef::try_from(value)
                .map_err(|e| format!("CA subject UTF8String: {e}"))?
                .as_str()
                .to_string(),
        )),
        der::Tag::Ia5String => Ok(rcgen::DnValue::Ia5String(
            rcgen::Ia5String::try_from(
                der::asn1::Ia5StringRef::try_from(value)
                    .map_err(|e| format!("CA subject IA5String: {e}"))?
                    .as_str(),
            )
            .map_err(|e| format!("CA subject IA5String content: {e}"))?,
        )),
        other => Err(format!(
            "CA subject attribute uses an unsupported string type (tag {other:?}) - the reconstruction must preserve it byte-for-byte"
        )),
    }
}

/// The CA hierarchy - Root CA and Intermediate CA, loaded or generated.
///
/// `root_cert` / `intermediate_cert` are `rcgen::Certificate` objects used
/// only as issuers when **signing new leaf certificates**. For serving the CA
/// chain to TLS clients (or to the trust store), use `root_cert_pem` /
/// `intermediate_cert_pem` instead - these preserve the original bytes from
/// disk (which carry the real issuer signature) rather than a self-signed
/// reconstruction.
pub struct CaHierarchy {
    /// Reconstructed `rcgen::Certificate` for the Root CA - used as an issuer
    /// when signing. NOT suitable for serving (it's self-signed even for the
    /// root, which is correct, but for the intermediate it would be wrong).
    pub root_cert: rcgen::Certificate,
    /// Private key of the Root CA.
    pub root_key: KeyPair,
    /// Reconstructed `rcgen::Certificate` for the Intermediate CA - used as
    /// the issuer when signing leaf certs. The reconstruction is self-signed
    /// (rcgen cannot re-sign an existing cert), so it MUST NOT be served to
    /// TLS clients - use `intermediate_cert_pem` for that.
    pub intermediate_cert: rcgen::Certificate,
    /// Private key of the Intermediate CA.
    pub intermediate_key: KeyPair,
    /// The Root CA certificate PEM bytes, as read from disk (or freshly
    /// generated). These bytes carry the real self-signed signature and are
    /// safe to serve to clients and install into trust stores.
    root_cert_pem: Vec<u8>,
    /// The Intermediate CA certificate PEM bytes, as read from disk (or
    /// freshly generated). These bytes carry the real signature from the
    /// Root CA - the `intermediate_cert` rcgen object cannot reproduce this,
    /// so TLS chains must use these bytes.
    intermediate_cert_pem: Vec<u8>,
}

/// Metadata stored alongside the Root CA.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CaMeta {
    /// When the hierarchy was created.
    pub created_at: DateTime<Utc>,
    /// SHA-256 fingerprint of the Root CA.
    pub root_ca_fingerprint: String,
    /// SHA-256 fingerprint of the Intermediate CA.
    pub intermediate_ca_fingerprint: String,
}

impl CaHierarchy {
    /// Load existing CA from disk, or generate a new one.
    pub fn ensure(config: &AcmeConfig) -> Result<Self, String> {
        config.init_dirs()?;

        if config.root_ca_cert_path().exists()
            && config.root_ca_key_path().exists()
            && config.intermediate_ca_cert_path().exists()
            && config.intermediate_ca_key_path().exists()
        {
            tracing::info!("Loading existing CA hierarchy from {:?}", config.ca_dir());
            return Self::load(config);
        }

        tracing::info!("Generating new CA hierarchy in {:?}", config.ca_dir());
        Self::generate(config)
    }

    fn load(config: &AcmeConfig) -> Result<Self, String> {
        let root_key_pem = std::fs::read_to_string(config.root_ca_key_path())
            .map_err(|e| format!("read root key: {e}"))?;
        let root_key =
            KeyPair::from_pem(&root_key_pem).map_err(|e| format!("parse root key: {e}"))?;

        // Read the on-disk Root CA cert PEM - these bytes carry the real
        // self-signed signature and are what we serve to clients / install
        // into the trust store.
        let root_cert_pem = std::fs::read(config.root_ca_cert_path())
            .map_err(|e| format!("read root cert: {e}"))?;
        // Reconstruct a rcgen::Certificate for the Root CA so we can use it
        // as an issuer when signing the intermediate (only needed on the
        // `generate` path; here we just need it for API symmetry / leaf
        // signing fallbacks). The DN is PARSED from the on-disk cert - the
        // reconstruction must mirror the real subject byte-for-byte
        // (PQCA-3: the leaf's issuer DN is chain-building state), never a
        // re-derivation that could diverge from the cert that was minted.
        let root_cert = Self::reconstruct_ca_cert_from_pem(
            &root_key,
            &root_cert_pem,
            config.root_ca_days,
        )?;

        let int_key_pem = std::fs::read_to_string(config.intermediate_ca_key_path())
            .map_err(|e| format!("read intermediate key: {e}"))?;
        let intermediate_key =
            KeyPair::from_pem(&int_key_pem).map_err(|e| format!("parse intermediate key: {e}"))?;

        // Read the on-disk Intermediate CA cert PEM - these bytes carry the
        // real signature from the Root CA. The reconstructed rcgen object
        // below is self-signed (rcgen cannot re-sign an existing cert), so we
        // MUST serve `intermediate_cert_pem`, not `intermediate_cert.pem()`.
        let intermediate_cert_pem = std::fs::read(config.intermediate_ca_cert_path())
            .map_err(|e| format!("read intermediate cert: {e}"))?;
        // DN-parsed reconstruction (see the root above): the issuer object's
        // DN mirrors the served intermediate's subject byte-for-byte.
        let intermediate_cert = Self::reconstruct_ca_cert_from_pem(
            &intermediate_key,
            &intermediate_cert_pem,
            config.intermediate_ca_days,
        )?;

        Ok(Self {
            root_cert,
            root_key,
            intermediate_cert,
            intermediate_key,
            root_cert_pem,
            intermediate_cert_pem,
        })
    }

    fn generate(config: &AcmeConfig) -> Result<Self, String> {
        // ── Root CA ──
        let root_key = KeyPair::generate().map_err(|e| format!("generate root key: {e}"))?;
        let root_cert = Self::build_root_cert(&root_key, config)?;

        // Persist Root CA
        let root_cert_pem_bytes = root_cert.pem();
        std::fs::write(config.root_ca_cert_path(), &root_cert_pem_bytes)
            .map_err(|e| format!("write root cert: {e}"))?;
        std::fs::write(config.root_ca_key_path(), root_key.serialize_pem())
            .map_err(|e| format!("write root key: {e}"))?;
        set_key_perms(&config.root_ca_key_path())?;

        // ── Intermediate CA ──
        let intermediate_key =
            KeyPair::generate().map_err(|e| format!("generate intermediate key: {e}"))?;
        let intermediate_cert = Self::build_intermediate_cert(
            &intermediate_key,
            &root_cert,
            &root_key,
            config,
        )?;

        // Persist Intermediate CA
        let intermediate_cert_pem = intermediate_cert.pem();
        std::fs::write(config.intermediate_ca_cert_path(), &intermediate_cert_pem)
            .map_err(|e| format!("write intermediate cert: {e}"))?;
        std::fs::write(
            config.intermediate_ca_key_path(),
            intermediate_key.serialize_pem(),
        )
        .map_err(|e| format!("write intermediate key: {e}"))?;
        set_key_perms(&config.intermediate_ca_key_path())?;

        Ok(Self {
            root_cert,
            root_key,
            intermediate_cert,
            intermediate_key,
            root_cert_pem: root_cert_pem_bytes.into_bytes(),
            intermediate_cert_pem: intermediate_cert_pem.into_bytes(),
        })
    }

    fn build_root_cert(
        root_key: &KeyPair,
        config: &AcmeConfig,
    ) -> Result<rcgen::Certificate, String> {
        let (root_cn, _) = ca_subject_common_names_for(config);
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, root_cn);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Sentin8");
        push_country_ca(&mut params.distinguished_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(config.root_ca_days as i64);
        params
            .self_signed(root_key)
            .map_err(|e| format!("self-sign root: {e}"))
    }

    fn build_intermediate_cert(
        int_key: &KeyPair,
        root_cert: &rcgen::Certificate,
        root_key: &KeyPair,
        config: &AcmeConfig,
    ) -> Result<rcgen::Certificate, String> {
        let (_, intermediate_cn) = ca_subject_common_names_for(config);
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, intermediate_cn);
        params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, CA_SUBJECT_OU);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Sentin8");
        push_country_ca(&mut params.distinguished_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        // webpki (rustls) builds chains by matching the child's AKI to the
        // parent's SKI - an intermediate WITHOUT an AKI cannot chain to the
        // root, and every rustls/sqlx client fails with UnknownIssuer
        // (OpenSSL chains by DN so psql still works - the divergence that
        // hid this). The flag makes rcgen embed the issuer's SKI.
        params.use_authority_key_identifier_extension = true;
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(config.intermediate_ca_days as i64);
        params
            .signed_by(int_key, root_cert, root_key)
            .map_err(|e| format!("sign intermediate: {e}"))
    }

    /// Reconstruct a self-signed rcgen certificate for an ON-DISK CA so it
    /// can serve as an issuer when signing leafs. The DN is parsed from
    /// the stored cert (`x509_cert`), so the reconstruction mirrors the
    /// served subject byte-for-byte - whatever subject the hierarchy was
    /// minted under (PQCA-3): a leaf's issuer DN is chain-building state
    /// (OpenSSL consumers match by subject/issuer DN), so the
    /// reconstruction may never re-derive or diverge from disk.
    ///
    /// Like every rcgen reconstruction this cert is self-signed (rcgen
    /// cannot re-sign an existing cert); it is NEVER served - the stored
    /// PEM bytes are the served truth.
    fn reconstruct_ca_cert_from_pem(
        key: &KeyPair,
        cert_pem: &[u8],
        days: u64,
    ) -> Result<rcgen::Certificate, String> {
        use base64::Engine as _;
        use der::Decode as _;

        // PEM -> DER (strip the armor, base64-decode the first block).
        let text = std::str::from_utf8(cert_pem).map_err(|e| format!("cert PEM utf8: {e}"))?;
        let stripped: String = text
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(stripped.trim())
            .map_err(|e| format!("cert base64: {e}"))?;
        let cert = x509_cert::certificate::Certificate::from_der(&der)
            .map_err(|e| format!("parse CA cert: {e}"))?;

        // Subject DN -> rcgen DistinguishedName, attribute by attribute,
        // in on-disk order (both are insertion-ordered). The STRING TYPE
        // is preserved byte-for-byte: webpki compares issuer/subject DNs
        // as raw DER, so a PrintableString `C=CA` rebuilt as UTF8String
        // breaks every leaf chain link with UnknownIssuer (rcgen's
        // `signed_by` copies the issuer DN from these params). Push the
        // typed DnValue, never `to_string()`.
        let mut dn = DistinguishedName::new();
        for atv in cert.tbs_certificate().subject().iter() {
            let arcs: Vec<u64> = atv.oid.arcs().map(u64::from).collect();
            let dn_type = DnType::from_oid(&arcs);
            dn.push(dn_type, atv_dn_value(&atv.value)?);
        }

        let mut params = CertificateParams::default();
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(days as i64);
        params
            .self_signed(key)
            .map_err(|e| format!("reconstruct CA: {e}"))
    }

    /// Sign a leaf certificate with the Intermediate CA.
    pub fn sign_leaf(
        &self,
        common_name: &str,
        san_dns_names: &[String],
        days: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let leaf_key = KeyPair::generate().map_err(|e| format!("generate leaf key: {e}"))?;

        let mut params = CertificateParams::new(san_dns_names.to_vec())
            .map_err(|e| format!("leaf params: {e}"))?;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        // RFC 5280 §4.2.1.9 + webpki: an end-entity cert MUST carry
        // BasicConstraints CA:FALSE explicitly - a leaf WITHOUT the
        // extension is rejected by webpki (rustls/sqlx) with UnknownIssuer
        // while OpenSSL accepts it (the divergence that hid this).
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // webpki (rustls) builds the chain more reliably with an Authority
        // Key Identifier referencing the issuing Intermediate CA's SKI.
        params.use_authority_key_identifier_extension = true;
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(days as i64);

        let leaf_cert = params
            .signed_by(&leaf_key, &self.intermediate_cert, &self.intermediate_key)
            .map_err(|e| format!("sign leaf: {e}"))?;

        // Return the full chain (leaf + intermediate) so TLS clients can
        // verify the leaf even when only the Root CA is in the trust store.
        let cert_pem = self.full_chain_pem(leaf_cert.pem().as_bytes());
        let key_pem = leaf_key.serialize_pem().into_bytes();
        Ok((cert_pem, key_pem))
    }

    /// Sign a client-authentication leaf certificate with the Intermediate
    /// CA.
    ///
    /// Same Intermediate CA as server leafs, but with EKU `ClientAuth`
    /// (RFC 5280 §4.2.1.12) - the profile difference that distinguishes a
    /// client certificate from a server certificate. Used for RFC 8705
    /// cert-bound M2M tokens (`self_signed_tls_client_auth`).
    pub fn sign_client_leaf(
        &self,
        common_name: &str,
        days: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let leaf_key = KeyPair::generate().map_err(|e| format!("generate leaf key: {e}"))?;

        let mut params = CertificateParams::new(vec![common_name.to_string()])
            .map_err(|e| format!("leaf params: {e}"))?;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        // RFC 5280 §4.2.1.9 + webpki: the explicit CA:FALSE
        // BasicConstraints (see `sign_leaf`).
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.use_authority_key_identifier_extension = true;
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(days as i64);

        let leaf_cert = params
            .signed_by(&leaf_key, &self.intermediate_cert, &self.intermediate_key)
            .map_err(|e| format!("sign client leaf: {e}"))?;

        // Full chain (leaf + intermediate) so the client can present a
        // complete chain in the mTLS handshake.
        let cert_pem = self.full_chain_pem(leaf_cert.pem().as_bytes());
        let key_pem = leaf_key.serialize_pem().into_bytes();
        Ok((cert_pem, key_pem))
    }

    /// Get the Root CA certificate PEM.
    ///
    /// Returns the on-disk bytes (which carry the real self-signed
    /// signature) rather than the reconstructed rcgen object's output -
    /// the latter is also self-signed for the root, but using the stored
    /// bytes keeps a single source of truth and avoids any future drift.
    pub fn root_ca_pem(&self) -> String {
        // Both the on-disk bytes and the reconstructed rcgen object are
        // self-signed for the root, so they're equivalent. Prefer the
        // stored bytes for consistency with the intermediate case.
        String::from_utf8_lossy(&self.root_cert_pem).into_owned()
    }

    /// Get the Intermediate CA certificate PEM.
    ///
    /// CRITICAL: returns the on-disk bytes (signed by the Root CA), NOT
    /// `self.intermediate_cert.pem()` - the rcgen reconstruction is
    /// self-signed (rcgen cannot re-sign an existing cert) and would break
    /// the leaf → intermediate → root chain for TLS clients.
    pub fn intermediate_ca_pem(&self) -> String {
        String::from_utf8_lossy(&self.intermediate_cert_pem).into_owned()
    }

    /// Get the full certificate chain (leaf + intermediate + root) for a leaf cert.
    pub fn full_chain_pem(&self, leaf_pem: &[u8]) -> Vec<u8> {
        let mut chain = leaf_pem.to_vec();
        chain.extend_from_slice(self.intermediate_ca_pem().as_bytes());
        chain.extend_from_slice(self.root_ca_pem().as_bytes());
        chain
    }

    /// Compute SHA-256 fingerprint of the Root CA cert PEM.
    pub fn root_ca_fingerprint(&self) -> String {
        let pem = self.root_ca_pem();
        let mut hasher = Sha256::new();
        hasher.update(pem.as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Set file permissions to 0600 for private keys (Unix only).
#[cfg(unix)]
/// Apply 0600 permissions to a private-key file (used for CA keys and
/// relay-persisted leaf keys alike).
pub(crate) fn set_key_perms(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| format!("set key perms: {e}"))
}

#[cfg(not(unix))]
fn set_key_perms(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Extract a PEM certificate chain's leaf NotAfter. Minimal DER walk -
/// decode the FIRST base64 PEM body, then locate the UTCTime/GeneralizedTime
/// in the validity sequence (same discipline the SDK's m2m load path uses:
/// no x509-parser dependency, fail toward "invalid" on any parse miss so
/// the caller re-mints rather than serving an unverifiable identity).
///
/// UTCTime encodes a two-digit year (`YY`, parsed as 2000+YY - dates are
/// 1950-2049 by RFC 5280); GeneralizedTime carries the full four digits.
pub fn pem_not_after(cert_pem: &str) -> Option<DateTime<Utc>> {
    use base64::Engine as _;
    let mut b64 = String::new();
    let mut inside = false;
    for line in cert_pem.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            inside = true;
            b64.clear();
            continue;
        }
        if line.contains("END CERTIFICATE") {
            break; // first block only - the leaf
        }
        if inside {
            b64.push_str(line.trim());
        }
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    der_not_after(&der)
}

/// DER walk: find the validity sequence and read its end time.
fn der_not_after(der: &[u8]) -> Option<DateTime<Utc>> {
    // Locate the validity window: two consecutive time values inside a
    // SEQUENCE. Scan for the first time-like tag, then parse the SECOND
    // time (NotBefore + NotAfter).
    let mut idx = 0usize;
    let mut times: Vec<(u8, &[u8])> = Vec::new();
    while idx + 2 < der.len() && times.len() < 2 {
        let tag = der[idx];
        let len = der[idx + 1] as usize;
        // UTCTime (0x17) and GeneralizedTime (0x18), short-form lengths
        // only (validity windows always are).
        if (tag == 0x17 || tag == 0x18) && len < 0x80 && idx + 2 + len <= der.len() {
            times.push((tag, &der[idx + 2..idx + 2 + len]));
            idx += 2 + len;
        } else {
            idx += 1;
        }
    }
    let (tag, not_after) = *times.get(1)?;
    parse_asn1_time(tag, not_after)
}

/// Parse an ASN.1 UTCTime/GeneralizedTime body into a UTC datetime.
fn parse_asn1_time(tag: u8, body: &[u8]) -> Option<DateTime<Utc>> {
    let s = std::str::from_utf8(body).ok()?.trim_end_matches('Z');
    // Field widths: UTCTime starts with a 2-digit year, GeneralizedTime
    // with 4 digits; both continue MMDDHHMMSS (seconds optional in
    // GeneralizedTime, always present in certs issued here).
    let (year, rest) = if tag == 0x17 {
        (2000 + s.get(0..2)?.parse::<i64>().ok()?, &s[2..])
    } else {
        (s.get(0..4)?.parse::<i64>().ok()?, &s[4..])
    };
    let two = |r: std::ops::Range<usize>| -> Option<i32> { rstr(rest, r).parse::<i32>().ok() };
    let month = two(0..2)?;
    let day = two(2..4)?;
    let hour = two(4..6)?;
    let min = two(6..8)?;
    let sec = two(8..10).unwrap_or(0);
    chrono::NaiveDate::from_ymd_opt(year as i32, month as u32, day as u32)?
        .and_hms_opt(hour as u32, min as u32, sec as u32)
        .map(|dt| dt.and_utc())
}

/// Safe substring helper for fixed-width time fields.
fn rstr(s: &str, r: std::ops::Range<usize>) -> &str {
    s.get(r).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn utc_time_parses() {
        // 261007073553Z → 2026-10-07 07:35:53 UTC (rcgen UTCTime form).
        let dt = parse_asn1_time(0x17, b"261007073553Z").expect("UTCTime");
        assert_eq!(dt.date_naive().year(), 2026);
        assert_eq!(dt.date_naive().month(), 10);
        assert_eq!(dt.date_naive().day(), 7);
    }

    #[test]
    fn generalized_time_parses() {
        let dt = parse_asn1_time(0x18, b"20301231235959Z").expect("GeneralizedTime");
        assert_eq!(dt.date_naive().year(), 2030);
        assert_eq!(dt.date_naive().month(), 12);
    }

    #[test]
    fn der_walk_finds_validity_pair() {
        // Minimal DER: two UTCTime bodies in sequence.
        let der = [
            0x30u8, 0x20, // SEQUENCE (noise)
            0x17, 13, // UTCTime NotBefore
            b'2', b'6', b'1', b'0', b'0', b'7', b'0', b'7', b'3', b'5', b'5', b'3', b'Z', 0x17,
            13, // UTCTime NotAfter
            b'2', b'7', b'0', b'1', b'0', b'5', b'0', b'7', b'3', b'5', b'5', b'3', b'Z',
        ];
        let dt = der_not_after(&der).expect("validity pair");
        assert_eq!(dt.date_naive().year(), 2027);
    }
}

#[cfg(test)]
mod notafter_live {
    use super::*;
    use chrono::Datelike;

    // Live check against a real rcgen leaf (the exact walk infra-tls uses).
    // Skipped when the material is absent (CI without a dev tree).
    #[test]
    fn live_leaf_not_after() {
        let path = "/home/hamid/dev/sentin8.new/.run/secrets/infra-tls/valkey-server.crt";
        let Ok(pem) = std::fs::read_to_string(path) else {
            eprintln!("skipped: {path} absent");
            return;
        };
        match pem_not_after(&pem) {
            Some(dt) => assert!(dt.date_naive().year() >= 2026, "not_after: {dt}"),
            None => panic!("PARSE FAILED on real leaf"),
        }
    }
}
