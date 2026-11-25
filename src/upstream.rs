// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Upstream ACME relay - a real RFC 8555 client for EXTERNAL domains
//! (acme DESIGN.md §4.2).
//!
//! The platform's own protocol surface (the `/acme/*` endpoints served to
//! `sentin8-tls` and other clients) is deliberately simple; this module is
//! the standards-compliant half that speaks to public CAs (Let's Encrypt,
//! ZeroSSL): ES256 JWS-signed requests (RFC 8555 §6.2), a persisted account
//! key + kid, fresh nonces per request, a real PKCS#10 CSR at finalize,
//! and HTTP-01 key authorizations captured for the proxy's :80 listener
//! to serve (acme DESIGN.md §4.3).
//!
//! TLS to the upstream rides a HYBRID provider: public ACME endpoints do
//! not offer X25519MLKEM768, so the platform's exclusive provider cannot
//! reach them - the relay negotiates classical TLS 1.2/1.3 (Graviola's
//! default composition) while every platform-internal listener stays
//! exclusive.

use base64::Engine;
use serde_json::{json, Value};

use crate::config::AcmeConfig;
use crate::dns01::DnsProvider;

/// b64url, no padding - the JOSE alphabet (RFC 7515 §2).
fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Persisted upstream ACME account (acme DESIGN.md §3 - data model).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpstreamAccount {
    /// The upstream account URL (the `kid` for JWS headers).
    pub kid: String,
    /// The ES256 account private key, PKCS#8 PEM (0600 on disk).
    pub key_pem: String,
}

/// A captured external order's remote state (embedded in the local order
/// record under `upstream`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpstreamOrder {
    /// The upstream order URL.
    pub url: String,
    /// Upstream authorization URLs.
    #[serde(default)]
    pub authorizations: Vec<String>,
    /// Upstream finalize URL.
    pub finalize: String,
    /// Upstream order status (`pending`/`ready`/`valid`/`invalid`).
    pub status: String,
    /// Upstream certificate URL once `valid`.
    #[serde(default)]
    pub certificate: Option<String>,
}

/// The challenge type an external order drives (CERTWILD-1, DESIGN
/// §4.2b): selected by identifier shape - a wildcard identifier routes
/// to DNS-01 (HTTP-01 cannot validate the covered name's nonexistent
/// HTTP endpoint), a plain hostname keeps HTTP-01.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengeKind {
    /// RFC 8555 §8.1 - token served at the well-known HTTP path.
    Http01,
    /// RFC 8555 §8.4 - key authorization in a TXT record.
    Dns01,
}

impl ChallengeKind {
    /// The ACME wire string for the challenge type.
    pub fn wire(&self) -> &'static str {
        match self {
            ChallengeKind::Http01 => "http-01",
            ChallengeKind::Dns01 => "dns-01",
        }
    }
}

/// Relay error surfaced to handlers: `Rejected` maps to a 4xx with the
/// upstream problem detail (no retry - permanent), `Unreachable` maps to
/// 502 (the caller may retry; the local order record keeps its state).
#[derive(Debug)]
pub enum UpstreamError {
    /// Upstream rejected the request - no retry (malformed, unauthorized…).
    Rejected(String),
    /// Transport / 5xx / parse failure - the caller may retry.
    Unreachable(String),
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamError::Rejected(d) => write!(f, "upstream rejected: {d}"),
            UpstreamError::Unreachable(d) => write!(f, "upstream unreachable: {d}"),
        }
    }
}

/// The relay's client surface over one upstream directory.
pub struct UpstreamClient {
    http: reqwest::Client,
    directory_url: String,
    contact: String,
    account_path: std::path::PathBuf,
    /// CERTENV-1 migration source: the pre-namespacing account file that
    /// sat at the mode root (`{data_dir}/upstream-account.json`), plus the
    /// hand-parked `upstream-account.staging.json` an earlier directory
    /// switch left behind. Read only when `account_path` is absent; the
    /// account is moved into its issuer environment's directory so the
    /// file and the kid that indexes it can never disagree.
    legacy_account_paths: Vec<std::path::PathBuf>,
    account: tokio::sync::RwLock<Option<UpstreamAccount>>,
    nonce: tokio::sync::RwLock<Option<String>>,
    /// HTTP-01 key authorizations captured at newOrder time, keyed by the
    /// upstream's challenge token - served by the
    /// `/.well-known/acme-challenge/{token}` route (DESIGN §4.3). The
    /// value carries the capture instant - the eviction bound is
    /// retention-time first (the validator's scheduling window), the
    /// hard count cap second (RIGMODE-1 eviction finding).
    pub challenge_tokens:
        std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, (std::time::Instant, String)>>>,
    /// The DNS-01 provider (CERTWILD-1, DESIGN §4.2b) - present only when
    /// a provider profile is configured; a wildcard order without it is
    /// rejected at new-order (fail-closed).
    pub dns: Option<std::sync::Arc<crate::dns01::CloudflareDns>>,
    /// Captured DNS-01 publish targets, keyed by challenge token: the
    /// TXT record name to clear when the order resolves or dies (a
    /// lingering TXT record keeps proving zone control after the order).
    dns01_records:
        std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
}

/// Sign one JOSE signing input with ES256 (RFC 7518 §3.4 - SHA-256 digest,
/// r||s signature) and return the base64url signature.
fn sign_es256(key: &p256::ecdsa::SigningKey, signing_input: &str) -> Result<String, String> {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::Digest;
    let digest = sha2::Sha256::digest(signing_input.as_bytes());
    let sig: p256::ecdsa::Signature = key
        .sign_prehash(&digest)
        .map_err(|e| format!("es256 sign: {e}"))?;
    Ok(b64(&sig.to_bytes()))
}

/// ES256 JWK (RFC 7518 §6.2.1) for the account public key.
fn jwk_from_key(key: &p256::ecdsa::SigningKey) -> Value {
    let point = key.verifying_key().to_encoded_point(false);
    let bytes = point.as_bytes();
    // Uncompressed point: 0x04 || X || Y (32 bytes each).
    let x = bytes.get(1..33).unwrap_or(&[0u8; 32]);
    let y = bytes.get(33..65).unwrap_or(&[0u8; 32]);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64(x),
        "y": b64(y),
    })
}

/// RFC 7638 thumbprint - base64url(SHA-256 of the canonical JWK members).
pub fn jwk_thumbprint(key: &p256::ecdsa::SigningKey) -> String {
    use sha2::Digest;
    let jwk = jwk_from_key(key);
    let canonical = json!({
        "crv": "P-256",
        "kty": "EC",
        "x": jwk["x"],
        "y": jwk["y"],
    });
    let digest = sha2::Sha256::digest(canonical.to_string().as_bytes());
    b64(&digest)
}

/// Load an ES256 signing key from a PKCS#8 PEM string.
fn load_key(pem: &str) -> Result<p256::ecdsa::SigningKey, UpstreamError> {
    use p256::pkcs8::DecodePrivateKey;
    p256::ecdsa::SigningKey::from_pkcs8_pem(pem)
        .map_err(|e| UpstreamError::Unreachable(format!("load account key: {e}")))
}

fn set_0600(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

/// The key authorization served at the well-known path and as the
/// dns-01 TXT value (RFC 8555 Section 8.1): `token "." Thumbprint` -
/// the digest half IS the account key's RFC 7638 thumbprint itself
/// (base64url of the SHA-256 over the canonical JWK), ONE hash total.
/// The earlier double-hash form (sha256 over the thumbprint STRING)
/// mismatched LE's validator live - LE expected `<token>.pLA8...` and
/// got the extra-hashed `<token>.u3SK...` (CERTTIER-1 public-mode run,
/// 2026-11-20).
fn key_authorization(token: &str, key: &p256::ecdsa::SigningKey) -> String {
    format!("{token}.{}", jwk_thumbprint(key))
}

/// Captured-token retention (RIGMODE-1 eviction finding). The plain
/// FIFO cap was NOT enough: the fleet's re-order loop (a service whose
/// cert fetch fails re-orders every backoff cycle) cycles 256 slots
/// within minutes, so a challenge token LE validates minutes after the
/// notify could 404 - and LE marks the challenge invalid on the fetch
/// miss. The map now bounds by TIME-TO-CONSUMPTION: a token lives at
/// least CHALLENGE_TOKEN_RETENTION_SECS since capture (the validator's
/// realistic scheduling window plus retries), and the hard cap still
/// bounds memory (the oldest PAST-retention entry evicts; a fresh
/// never-bounded entry is never dropped while under the cap).
const CHALLENGE_TOKEN_RETENTION_SECS: u64 = 600;
const MAX_CHALLENGE_TOKENS: usize = 256;

impl UpstreamClient {
    /// Build the relay over `config`. The reqwest client rides a HYBRID
    /// rustls config (Graviola default provider - X25519MLKEM768 first,
    /// classical fallback, TLS 1.2/1.3): the platform's exclusive provider
    /// speaks only X25519MLKEM768 and cannot reach public ACME endpoints.
    /// Roots: the pinned PEM bundle when `upstream_ca_pem` is set, else
    /// the system native roots.
    pub fn new(config: &AcmeConfig) -> Result<Self, String> {
        let provider = rustls_graviola::default_provider();
        let mut roots = rustls::RootCertStore::empty();
        if !config.upstream_ca_pem.is_empty() {
            let pem = std::fs::read_to_string(&config.upstream_ca_pem)
                .map_err(|e| format!("read upstream CA pem: {e}"))?;
            let mut cursor = std::io::Cursor::new(pem.as_bytes());
            for cert in rustls_pemfile::certs(&mut cursor) {
                let cert = cert.map_err(|e| format!("parse upstream CA pem: {e}"))?;
                roots
                    .add(cert)
                    .map_err(|e| format!("add upstream CA cert: {e}"))?;
            }
        } else {
            for cert in rustls_native_certs::load_native_certs()
                .map_err(|e| format!("native roots: {e}"))?
            {
                roots
                    .add(cert)
                    .map_err(|e| format!("add native cert: {e}"))?;
            }
        }
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("tls versions: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(20))
            .use_preconfigured_tls(tls)
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        // DNS-01 provider (CERTWILD-1): built only for a known provider
        // name; an unknown name fails the boot (a typo silently
        // degrading wildcard orders to reject-at-new-order hides the
        // misconfiguration).
        let dns = match config.dns_provider.as_str() {
            "" => None,
            "cloudflare" => Some(std::sync::Arc::new(
                crate::dns01::CloudflareDns::new(config)?,
            )),
            other => {
                return Err(format!(
                    "unknown SENTIN8_ACME_DNS_PROVIDER '{other}' (supported: cloudflare)"
                ))
            }
        };
        Ok(Self {
            http,
            directory_url: config.upstream_directory_url.clone(),
            contact: config.upstream_contact.clone(),
            account_path: config.upstream_account_path(),
            legacy_account_paths: vec![
                config.data_dir.join("upstream-account.json"),
                config.data_dir.join("upstream-account.staging.json"),
                config.data_dir.join("upstream-account.production.json"),
            ],
            account: Default::default(),
            nonce: Default::default(),
            challenge_tokens: Default::default(),
            dns,
            dns01_records: Default::default(),
        })
    }

    /// Adopt a pre-namespacing account file into this client's issuer
    /// directory (CERTENV-1), returning it on success.
    ///
    /// The ACCOUNT KEY is directory-agnostic (an ES256 private key), but
    /// the KID is not: it carries the directory that issued it
    /// (`https://acme-v02.../acme/acct/123`). So the adoption is decided by
    /// the kid's authority, compared against this client's directory URL -
    /// a staging account is adopted only by the staging client, a
    /// production account only by the production one. A mismatch is
    /// skipped (NOT an error): the caller falls through to a fresh
    /// registration against the directory it actually targets.
    ///
    /// On adoption the file is MOVED (not copied) into the environment's
    /// directory, so the fleet converges on one account per environment and
    /// the mode root stops carrying issuer state.
    fn adopt_legacy_account(&self) -> Option<UpstreamAccount> {
        let authority = |url: &str| -> String {
            url.trim()
                .split("://")
                .nth(1)
                .unwrap_or(url)
                .split('/')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase()
        };
        let wanted = authority(&self.directory_url);
        for legacy in &self.legacy_account_paths {
            if legacy == &self.account_path {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(legacy) else {
                continue;
            };
            let Ok(acct) = serde_json::from_str::<UpstreamAccount>(&text) else {
                continue;
            };
            if authority(&acct.kid) != wanted {
                continue;
            }
            if let Some(dir) = self.account_path.parent() {
                if std::fs::create_dir_all(dir).is_err() {
                    continue;
                }
            }
            match std::fs::write(&self.account_path, serde_json::to_string(&acct).unwrap()) {
                Ok(()) => {
                    set_0600(&self.account_path);
                    let _ = std::fs::remove_file(legacy);
                    tracing::info!(
                        from = %legacy.display(),
                        to = %self.account_path.display(),
                        kid = %acct.kid,
                        "acme: adopted legacy upstream account into its issuer environment (CERTENV-1)"
                    );
                    return Some(acct);
                }
                Err(e) => {
                    tracing::warn!(
                        from = %legacy.display(),
                        error = %e,
                        "acme: legacy account adoption failed - will register fresh"
                    );
                }
            }
        }
        None
    }

    async fn fetch_directory(&self) -> Result<Value, UpstreamError> {
        let resp = self
            .http
            .get(&self.directory_url)
            .send()
            .await
            .map_err(|e| UpstreamError::Unreachable(format!("directory: {e}")))?;
        resp.json()
            .await
            .map_err(|e| UpstreamError::Unreachable(format!("directory parse: {e}")))
    }

    async fn fresh_nonce(&self) -> Result<String, UpstreamError> {
        let dir = self.fetch_directory().await?;
        let url = str_field(&dir, "newNonce")?;
        let resp = self
            .http
            .head(&url)
            .send()
            .await
            .map_err(|e| UpstreamError::Unreachable(format!("new-nonce: {e}")))?;
        header(&resp, "Replay-Nonce")
            .map(|s| s.to_string())
            .ok_or_else(|| UpstreamError::Unreachable("new-nonce: missing header".into()))
    }

    async fn take_nonce(&self) -> Result<String, UpstreamError> {
        if let Some(n) = self.nonce.write().await.take() {
            return Ok(n);
        }
        self.fresh_nonce().await
    }

    /// Load or register the upstream account (idempotent across boots; the
    /// key + kid persist at `{data_dir}/upstream/{env}/account.json`, 0600 -
    /// CERTENV-1 keeps one account per issuer environment).
    async fn ensure_account(&self) -> Result<UpstreamAccount, UpstreamError> {
        if let Some(acct) = self.account.read().await.clone() {
            return Ok(acct);
        }
        if let Ok(text) = std::fs::read_to_string(&self.account_path) {
            if let Ok(acct) = serde_json::from_str::<UpstreamAccount>(&text) {
                *self.account.write().await = Some(acct.clone());
                return Ok(acct);
            }
        }
        // CERTENV-1 migration: the account file predates issuer
        // namespacing, so it sits at the mode root. Adopt it ONLY when its
        // kid names the directory this client is configured against -
        // adopting a foreign kid would reproduce the exact permanent
        // `accountDoesNotExist` the namespacing exists to prevent.
        if let Some(acct) = self.adopt_legacy_account() {
            *self.account.write().await = Some(acct.clone());
            return Ok(acct);
        }
        // First use: generate the ES256 key and register the account with
        // the JWK embedded in the protected header (RFC 8555 §7.4 - JWK
        // mode is ONLY for the initial newAccount; every subsequent
        // request is kid-mode).
        use p256::pkcs8::EncodePrivateKey;
        let key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let key_pem = key
            .to_pkcs8_pem(base64ct::LineEnding::LF)
            .map_err(|e| UpstreamError::Unreachable(format!("account key serialize: {e}")))?
            .to_string();
        let jwk = jwk_from_key(&key);
        let dir = self.fetch_directory().await?;
        let url = str_field(&dir, "newAccount")?;
        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{}", self.contact)],
        });
        let nonce = self.take_nonce().await?;
        let protected = json!({
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
            "jwk": jwk,
        });
        let protected_b64 = b64(protected.to_string().as_bytes());
        let payload_b64 = b64(payload.to_string().as_bytes());
        let sig = sign_es256(&key, &format!("{protected_b64}.{payload_b64}"))
            .map_err(UpstreamError::Unreachable)?;
        let body = json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": sig,
        });
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/jose+json")
            .json(&body)
            .send()
            .await
            .map_err(|e| UpstreamError::Unreachable(format!("new-account: {e}")))?;
        // A rejected account creation currently surfaced as the bare
        // 'new-account: no Location' Unreachable (mapped to a causeless
        // 502; LE's real answer - e.g. invalidContact on the configured
        // address - stayed invisible). Read the status first: a 4xx is a
        // REJECTED order (the caller's body carries LE's problem detail),
        // a 5xx stays Unreachable. 2xx carries the kid Location.
        let status = resp.status();
        if !(200..300).contains(&status.as_u16()) {
            let detail = problem_detail(resp).await;
            return Err(UpstreamError::Rejected(format!(
                "new-account {status}: {detail}"
            )));
        }
        let kid = header(&resp, "Location")
            .map(|s| s.to_string())
            .ok_or_else(|| {
                UpstreamError::Unreachable("new-account: no Location".into())
            })?;
        if let Some(n) = header(&resp, "Replay-Nonce") {
            *self.nonce.write().await = Some(n.to_string());
        }
        let acct = UpstreamAccount { kid, key_pem };
        if let Some(dir) = self.account_path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| UpstreamError::Unreachable(format!("persist account: {e}")))?;
        }
        std::fs::write(&self.account_path, serde_json::to_string(&acct).unwrap())
            .map_err(|e| UpstreamError::Unreachable(format!("persist account: {e}")))?;
        set_0600(&self.account_path);
        *self.account.write().await = Some(acct.clone());
        Ok(acct)
    }

    /// POST-as-GET (RFC 8555 §6.3): the payload member is the EMPTY
    /// string (""), not an encoded object. LE rejects `{}`/`null`
    /// payloads with `POST-as-GET requests must have an empty payload`
    /// (found live on the first public-mode run) - the challenge-ready
    /// notify, order poll, and certificate download all ride this form.
    async fn post_kid_empty_payload(&self, url: &str) -> Result<reqwest::Response, UpstreamError> {
        let acct = self.ensure_account().await?;
        let key = load_key(&acct.key_pem)?;
        for attempt in 0..2 {
            let nonce = self.take_nonce().await?;
            let protected = json!({
                "alg": "ES256",
                "nonce": nonce,
                "url": url,
                "kid": acct.kid,
            });
            let protected_b64 = b64(protected.to_string().as_bytes());
            let payload_b64 = ""; // RFC 8555 6.3: payload = empty string
            let sig = sign_es256(&key, &format!("{protected_b64}.{payload_b64}"))
                .map_err(UpstreamError::Unreachable)?;
            let body = json!({
                "protected": protected_b64,
                "payload": payload_b64,
                "signature": sig,
            });
            let resp = self
                .http
                .post(url)
                .header("Content-Type", "application/jose+json")
                .json(&body)
                .send()
                .await
                .map_err(|e| UpstreamError::Unreachable(format!("post {url}: {e}")))?;
            let status = resp.status();
            if status.as_u16() == 400 {
                let text = resp.text().await.unwrap_or_default();
                if text.contains("badNonce") {
                    if attempt == 0 {
                        *self.nonce.write().await = None;
                        continue;
                    }
                    return Err(UpstreamError::Unreachable(
                        "badNonce persisted after replay".into(),
                    ));
                }
                return Err(UpstreamError::Rejected(format!(
                    "{status}: {}",
                    short(&text)
                )));
            }
            if let Some(n) = header(&resp, "Replay-Nonce") {
                *self.nonce.write().await = Some(n.to_string());
            }
            return Ok(resp);
        }
        Err(UpstreamError::Unreachable(
            "post_kid: unreachable retry loop".into(),
        ))
    }

    /// kid-mode JWS POST (account-scoped, RFC 8555 §6.2). A `badNonce`
    /// response is retried ONCE with a fresh nonce.
    async fn post_kid(
        &self,
        url: &str,
        payload: &Value,
    ) -> Result<reqwest::Response, UpstreamError> {
        let acct = self.ensure_account().await?;
        let key = load_key(&acct.key_pem)?;
        for attempt in 0..2 {
            let nonce = self.take_nonce().await?;
            let protected = json!({
                "alg": "ES256",
                "nonce": nonce,
                "url": url,
                "kid": acct.kid,
            });
            let protected_b64 = b64(protected.to_string().as_bytes());
            let payload_b64 = b64(payload.to_string().as_bytes());
            let sig = sign_es256(&key, &format!("{protected_b64}.{payload_b64}"))
                .map_err(UpstreamError::Unreachable)?;
            let body = json!({
                "protected": protected_b64,
                "payload": payload_b64,
                "signature": sig,
            });
            let resp = self
                .http
                .post(url)
                .header("Content-Type", "application/jose+json")
                .json(&body)
                .send()
                .await
                .map_err(|e| UpstreamError::Unreachable(format!("post {url}: {e}")))?;
            let status = resp.status();
            // badNonce: retry once with a fresh nonce (DESIGN §4.2).
            if status.as_u16() == 400 {
                let text = resp.text().await.unwrap_or_default();
                if text.contains("badNonce") {
                    if attempt == 0 {
                        *self.nonce.write().await = None;
                        continue;
                    }
                    return Err(UpstreamError::Unreachable(
                        "badNonce persisted after replay".into(),
                    ));
                }
                return Err(UpstreamError::Rejected(format!(
                    "{status}: {}",
                    short(&text)
                )));
            }
            if let Some(n) = header(&resp, "Replay-Nonce") {
                *self.nonce.write().await = Some(n.to_string());
            }
            return Ok(resp);
        }
        Err(UpstreamError::Unreachable(
            "post_kid: unreachable retry loop".into(),
        ))
    }

    /// Submit a newOrder for the identifier. The challenge type is
    /// selected by identifier shape (CERTWILD-1, DESIGN §4.2b): a
    /// wildcard routes to DNS-01 (TXT published through the provider),
    /// a plain hostname keeps HTTP-01 (the key authorization is captured
    /// into the bounded challenge map for the proxy's :80 listener).
    pub async fn new_order(
        &self,
        domain: &str,
    ) -> Result<(UpstreamOrder, String, String, ChallengeKind), UpstreamError> {
        let kind = if domain.starts_with("*.") {
            ChallengeKind::Dns01
        } else {
            ChallengeKind::Http01
        };
        // Fail-closed (DESIGN §4.2b): a wildcard order without a DNS
        // provider can never validate - reject at the order site, not
        // mid-challenge.
        if kind == ChallengeKind::Dns01 && self.dns.is_none() {
            return Err(UpstreamError::Rejected(
                "wildcard identifiers require the dns-01 challenge but no DNS provider is configured (SENTIN8_ACME_DNS_PROVIDER/_API_TOKEN/_ZONE)".into(),
            ));
        }
        let dir = self.fetch_directory().await?;
        let url = str_field(&dir, "newOrder")?;
        let payload = json!({
            "identifiers": [{"type": "dns", "value": domain}],
        });
        let resp = self.post_kid(&url, &payload).await?;
        let status = resp.status();
        if !(200..300).contains(&status.as_u16()) {
            return Err(UpstreamError::Rejected(format!(
                "new-order {status}: {}",
                problem_detail(resp).await
            )));
        }
        let order_url = header(&resp, "Location")
            .map(|s| s.to_string())
            .ok_or_else(|| UpstreamError::Unreachable("new-order: no Location".into()))?;
        let order: Value = resp
            .json()
            .await
            .map_err(|e| UpstreamError::Unreachable(format!("new-order parse: {e}")))?;
        let authorizations = order
            .get("authorizations")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>();
        let finalize = str_field(&order, "finalize")?;
        // Find the challenge for the identifier's shape in the first
        // authz: the token + URL for HTTP-01 (served from the bounded
        // map), the token for DNS-01 (TXT published via the provider).
        let mut token = String::new();
        let mut challenge_url = String::new();
        if let Some(authz_url) = authorizations.first() {
            let resp = self
                .http
                .get(authz_url)
                .send()
                .await
                .map_err(|e| UpstreamError::Unreachable(format!("authz: {e}")))?;
            let authz: Value = resp
                .json()
                .await
                .map_err(|e| UpstreamError::Unreachable(format!("authz parse: {e}")))?;
            for ch in authz
                .get("challenges")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
            {
                if ch.get("type").and_then(|v| v.as_str()) == Some(kind.wire()) {
                    token = ch
                        .get("token")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    challenge_url = ch
                        .get("url")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    break;
                }
            }
        }
        if token.is_empty() || challenge_url.is_empty() {
            return Err(UpstreamError::Rejected(format!(
                "new-order: upstream offered no {} challenge",
                kind.wire()
            )));
        }
        let acct = self.ensure_account().await?;
        let key = load_key(&acct.key_pem)?;
        let key_auth = key_authorization(&token, &key);
        match kind {
            ChallengeKind::Http01 => {
                let now = std::time::Instant::now();
                let mut map = self.challenge_tokens.write().await;
                if map.len() >= MAX_CHALLENGE_TOKENS {
                    // Bounded: evict the OLDEST PAST-RETENTION entry (a token
                    // inside its validator window is never dropped while slots
                    // remain). In the pathological all-pending flood - every
                    // entry inside retention - the oldest still goes, keeping
                    // the hard memory bound.
                    let victim = map
                        .iter()
                        .filter(|(_, (at, _))| {
                            at.elapsed()
                                >= std::time::Duration::from_secs(CHALLENGE_TOKEN_RETENTION_SECS)
                        })
                        .min_by_key(|(_, (at, _))| *at)
                        .map(|(t, _)| t.clone())
                        .or_else(|| {
                            map.iter()
                                .min_by_key(|(_, (at, _))| *at)
                                .map(|(t, _)| t.clone())
                        });
                    if let Some(v) = victim {
                        map.remove(&v);
                    }
                }
                map.insert(token.clone(), (now, key_auth));
            }
            ChallengeKind::Dns01 => {
                // Publish the TXT record now (DESIGN §4.2b): the record
                // must be live before the challenge notify - the
                // upstream validates on its own schedule. The covered
                // zone drops the `*.` label (RFC 8555 §8.4).
                let covered = domain.strip_prefix("*.").unwrap_or(domain);
                let record = crate::dns01::CloudflareDns::txt_record_name(covered);
                if let Some(dns) = &self.dns {
                    dns.publish_txt(&record, &key_auth)
                        .await
                        .map_err(UpstreamError::Unreachable)?;
                }
                // Track the publish target for the order-window clear.
                self.dns01_records
                    .write()
                    .await
                    .insert(token.clone(), record);
            }
        }
        Ok((UpstreamOrder {
            url: order_url,
            authorizations,
            finalize,
            status: "pending".into(),
            certificate: None,
        }, token, challenge_url, kind))
    }

    /// Respond to the challenge - the RFC 8555 §7.5.1 activate POST.
    ///
    /// The CHALLENGE RESPONSE is NOT a POST-as-GET: RFC 8555 §7.5.1
    /// requires the payload to be an EMPTY JSON OBJECT (`{}` - the JWS
    /// body's "payload" field carries `base64url({})`), which tells the
    /// CA "begin validating". An empty-STRING payload (POST-as-GET,
    /// RFC §6.3) only READS the challenge - the CA answers 200 with the
    /// still-pending challenge object and NEVER starts its validator
    /// (found live, CERTTIER-1 public-mode run 2026-11-20: two orders
    /// stayed `pending` for 40+ minutes with the token proven servable
    /// from three continents, until the payload form was corrected;
    /// the earlier RIGMODE-1 note that `{}` 400s was an
    /// over-generalized fix - the {} 400 it observed belonged to the
    /// POST-as-GET resources, not the challenge response).
    pub async fn notify_challenge(&self, challenge_url: &str) -> Result<(), UpstreamError> {
        let resp = self.post_kid(challenge_url, &json!({})).await?;
        let status = resp.status();
        if !(200..300).contains(&status.as_u16()) {
            return Err(UpstreamError::Rejected(format!(
                "challenge-notify {status}: {}",
                problem_detail(resp).await
            )));
        }
        Ok(())
    }

    /// Finalize with a REAL PKCS#10 CSR (rcgen key + CertificateParams -
    /// acme owns the certificate's private key; the caller's placeholder
    /// is never forwarded). Returns the CSR key PEM so the handler can
    /// persist it next to the issued certificate.
    ///
    /// RFC 8555 §7.4 sequencing: the upstream order must reach `ready`
    /// (its authorizations valid) BEFORE the CSR is submitted - a public
    /// CA validates the challenge asynchronously (LE staging: 10-60s),
    /// so finalize first polls the order until it leaves `pending`
    /// (bounded - the same window shape as `poll_order`), THEN submits
    /// the CSR. Submitting against a `pending` order is a guaranteed
    /// `orderNotReady` 403 whose error path would otherwise drop the
    /// challenge proof while the validator still needs it (found live,
    /// CERTTIER-1 public-mode run 2026-11-20).
    pub async fn finalize(
        &self,
        order: &UpstreamOrder,
        domain: &str,
    ) -> Result<(UpstreamOrder, String), UpstreamError> {
        // Wait for the upstream order to become finalizable: `ready`
        // (all authorizations valid) or `processing`/`valid` (already
        // finalized by an earlier attempt). A `pending` order keeps the
        // loop; `invalid` is terminal.
        let mut settled = order.clone();
        for _ in 0..120 {
            let resp = self.post_kid_empty_payload(&order.url).await?;
            let status = resp.status();
            if !(200..300).contains(&status.as_u16()) {
                return Err(UpstreamError::Rejected(format!(
                    "poll {status}: {}",
                    problem_detail(resp).await
                )));
            }
            let order_json: Value = resp
                .json()
                .await
                .map_err(|e| UpstreamError::Unreachable(format!("poll parse: {e}")))?;
            settled = order.clone();
            settled.status = str_or(&order_json, "status", "processing");
            settled.certificate = order_json
                .get("certificate")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            match settled.status.as_str() {
                "ready" | "processing" | "valid" => break,
                "invalid" => {
                    return Err(UpstreamError::Rejected(
                        "upstream order invalid during pre-finalize poll".into(),
                    ))
                }
                _ => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
            }
        }
        if settled.status == "pending" {
            return Err(UpstreamError::Unreachable(
                "pre-finalize poll: exhausted attempts (upstream order still pending)".into(),
            ));
        }
        let order = &settled;

        let csr_key = rcgen::KeyPair::generate()
            .map_err(|e| UpstreamError::Unreachable(format!("csr key: {e}")))?;
        // A wildcard identifier's CSR carries the wildcard SAN exactly as
        // ordered (`*.zone` - RFC 8555 §7.1.3 admits the wildcard form
        // in the CSR); the CN keeps the same value.
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| UpstreamError::Unreachable(format!("csr params: {e}")))?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, domain);
        let csr = params
            .serialize_request(&csr_key)
            .map_err(|e| UpstreamError::Unreachable(format!("csr serialize: {e}")))?;
        let csr_b64 = b64(csr.der());
        let payload = json!({ "csr": csr_b64 });
        let resp = self.post_kid(&order.finalize, &payload).await?;
        let status = resp.status();
        if !(200..300).contains(&status.as_u16()) {
            return Err(UpstreamError::Rejected(format!(
                "finalize {status}: {}",
                problem_detail(resp).await
            )));
        }
        let order_json: Value = resp
            .json()
            .await
            .map_err(|e| UpstreamError::Unreachable(format!("finalize parse: {e}")))?;
        let mut new_order = order.clone();
        new_order.status = str_or(&order_json, "status", "processing");
        new_order.certificate = order_json
            .get("certificate")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Ok((new_order, csr_key.serialize_pem()))
    }

    /// Poll the upstream order until terminal (bounded attempts, 500ms
    /// apart - the http-01 validation round trip is upstream-side). A
    /// public CA validates the challenge asynchronously: LE staging
    /// commonly takes 10-60s (multi-perspective validation fleets), so
    /// the window must cover a FULL validation cycle - 120 attempts at
    /// 500ms (60s) - not the original 10s ceiling, which turned a healthy
    /// external mint into `poll: exhausted attempts` (RIGMODE-1).
    pub async fn poll_order(&self, order: &UpstreamOrder) -> Result<UpstreamOrder, UpstreamError> {
        for _ in 0..120 {
            let resp = self.post_kid_empty_payload(&order.url).await?;
            let status = resp.status();
            if !(200..300).contains(&status.as_u16()) {
                return Err(UpstreamError::Rejected(format!(
                    "poll {status}: {}",
                    problem_detail(resp).await
                )));
            }
            let order_json: Value = resp
                .json()
                .await
                .map_err(|e| UpstreamError::Unreachable(format!("poll parse: {e}")))?;
            let mut new_order = order.clone();
            new_order.status = str_or(&order_json, "status", "processing");
            new_order.certificate = order_json
                .get("certificate")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            match new_order.status.as_str() {
                "valid" => return Ok(new_order),
                "invalid" => return Err(UpstreamError::Rejected("upstream order invalid".into())),
                _ => {}
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        Err(UpstreamError::Unreachable(
            "poll: exhausted attempts".into(),
        ))
    }

    /// Download the certificate chain (POST-as-GET, RFC 8555 §6.3); the
    /// PEM text is cached by the handler under `certificates/{id}`.
    pub async fn download_cert(&self, cert_url: &str) -> Result<String, UpstreamError> {
        let resp = self.post_kid_empty_payload(cert_url).await?;
        let status = resp.status();
        if !(200..300).contains(&status.as_u16()) {
            return Err(UpstreamError::Unreachable(format!("cert fetch {status}")));
        }
        resp.text()
            .await
            .map_err(|e| UpstreamError::Unreachable(format!("cert read: {e}")))
    }

    /// Drop a captured challenge (order completed - success or
    /// failure; the proof must not linger servable): the HTTP-01 key
    /// authorization leaves the bounded map; a DNS-01 TXT record is
    /// cleared at the provider (DESIGN §4.2b - a lingering record
    /// keeps proving zone control after the order).
    pub async fn forget_token(&self, token: &str) {
        self.challenge_tokens.write().await.remove(token);
        if let Some(record) = self.dns01_records.write().await.remove(token) {
            if let Some(dns) = &self.dns {
                if let Err(e) = dns.clear_txt(&record).await {
                    tracing::warn!(record = %record, error = %e,
                        "acme: dns-01 TXT clear failed - remove the record manually");
                }
            }
        }
    }
}

fn header<'a>(resp: &'a reqwest::Response, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

fn str_field(json: &Value, field: &str) -> Result<String, UpstreamError> {
    json.get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| UpstreamError::Unreachable(format!("directory: missing {field}")))
}

fn str_or(json: &Value, field: &str, default: &str) -> String {
    json.get(field)
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

fn short(text: &str) -> String {
    text.chars().take(200).collect()
}

async fn problem_detail(resp: reqwest::Response) -> String {
    match resp.text().await {
        Ok(t) => short(&t),
        Err(_) => String::new(),
    }
}
