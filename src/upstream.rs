// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Upstream ACME relay - a real RFC 8555 client for EXTERNAL domains
//! (DEVDOM-2, acme DESIGN.md §4.2).
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

/// b64url, no padding - the JOSE alphabet (RFC 7515 §2).
fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Cap on captured http-01 key authorizations (bounded map - a stuck
/// upstream can never grow acme's memory unbounded).
const MAX_CHALLENGE_TOKENS: usize = 256;

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
    account: tokio::sync::RwLock<Option<UpstreamAccount>>,
    nonce: tokio::sync::RwLock<Option<String>>,
    /// HTTP-01 key authorizations captured at newOrder time, keyed by the
    /// upstream's challenge token - served by the
    /// `/.well-known/acme-challenge/{token}` route (bounded, DESIGN §4.3).
    pub challenge_tokens:
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

/// The http-01 key authorization served at the well-known path (RFC 8555
/// §8.1): `token "." base64url(sha256(thumbprint(account key)))`.
fn key_authorization(token: &str, key: &p256::ecdsa::SigningKey) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(jwk_thumbprint(key).as_bytes());
    format!("{token}.{}", b64(&digest))
}

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
        Ok(Self {
            http,
            directory_url: config.upstream_directory_url.clone(),
            contact: config.upstream_contact.clone(),
            account_path: config.upstream_account_path(),
            account: Default::default(),
            nonce: Default::default(),
            challenge_tokens: Default::default(),
        })
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
    /// key + kid persist at `upstream-account.json`, 0600).
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
        let kid = header(&resp, "Location")
            .map(|s| s.to_string())
            .ok_or_else(|| UpstreamError::Unreachable("new-account: no Location".into()))?;
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

    /// Submit a newOrder for the identifier. On success the http-01 key
    /// authorization is captured into the bounded challenge map (served by
    /// the proxy's :80 listener → acme's well-known route).
    pub async fn new_order(
        &self,
        domain: &str,
    ) -> Result<(UpstreamOrder, String, String), UpstreamError> {
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
        // Find the http-01 challenge in the first authz and capture the
        // key authorization the proxy's :80 listener will serve.
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
                if ch.get("type").and_then(|v| v.as_str()) == Some("http-01") {
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
            return Err(UpstreamError::Rejected(
                "new-order: upstream offered no http-01 challenge".into(),
            ));
        }
        let acct = self.ensure_account().await?;
        let key = load_key(&acct.key_pem)?;
        let key_auth = key_authorization(&token, &key);
        let mut map = self.challenge_tokens.write().await;
        if map.len() >= MAX_CHALLENGE_TOKENS {
            // Bounded: evict the oldest captured token.
            if let Some(first) = map.keys().next().cloned() {
                map.remove(&first);
            }
        }
        map.insert(token.clone(), key_auth);
        Ok((
            UpstreamOrder {
                url: order_url,
                authorizations,
                finalize,
                status: "pending".into(),
                certificate: None,
            },
            token,
            challenge_url,
        ))
    }

    /// Notify the upstream the http-01 challenge is ready for validation -
    /// the upstream then fetches the key authorization from the proxy's
    /// :80 listener (DESIGN §4.3).
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
    pub async fn finalize(
        &self,
        order: &UpstreamOrder,
        domain: &str,
    ) -> Result<(UpstreamOrder, String), UpstreamError> {
        let csr_key = rcgen::KeyPair::generate()
            .map_err(|e| UpstreamError::Unreachable(format!("csr key: {e}")))?;
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
    /// apart - the http-01 validation round trip is upstream-side).
    pub async fn poll_order(&self, order: &UpstreamOrder) -> Result<UpstreamOrder, UpstreamError> {
        for _ in 0..20 {
            let resp = self.post_kid(&order.url, &json!({})).await?;
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
        let resp = self.post_kid(cert_url, &json!(null)).await?;
        let status = resp.status();
        if !(200..300).contains(&status.as_u16()) {
            return Err(UpstreamError::Unreachable(format!("cert fetch {status}")));
        }
        resp.text()
            .await
            .map_err(|e| UpstreamError::Unreachable(format!("cert read: {e}")))
    }

    /// Drop a captured key authorization (order completed - success or
    /// failure; the token must not linger servable).
    pub async fn forget_token(&self, token: &str) {
        self.challenge_tokens.write().await.remove(token);
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
