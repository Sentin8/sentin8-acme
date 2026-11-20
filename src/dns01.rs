// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! DNS-01 challenge automation (CERTWILD-1, acme DESIGN.md §4.2b).
//!
//! Wildcard identifiers (`*.{env_domain}`) cannot be validated by
//! HTTP-01 - RFC 8555 §8.4 requires the DNS-01 challenge, whose proof
//! is a TXT record at `_acme-challenge.{covered-zone}`. This module
//! publishes and clears that record through a bounded set of DNS
//! provider APIs (currently Cloudflare), selected by
//! `SENTIN8_ACME_DNS_PROVIDER`.
//!
//! The API token is operator-scoped to the challenge zone's DNS edit
//! permission ONLY (Cloudflare `Zone.DNS:Edit`) - never the whole
//! account. Acme holds the token for the challenge window and clears
//! the record as soon as the authorization resolves (or the order
//! dies); a lingering servable TXT record would keep proving control
//! of the zone after the order is done.

use serde_json::Value;

use crate::config::AcmeConfig;

/// A DNS provider integration able to publish + clear the DNS-01 TXT
/// record for one zone. The bounded set is deliberately small: a
/// provider the operator cannot prove token authority over is never
/// attempted (DESIGN §4.2b).
pub trait DnsProvider: Send + Sync {
    /// Publish the TXT record `_acme-challenge.{zone}` with `value`.
    /// Idempotent: publishing an identical record twice is a no-op.
    fn publish_txt(
        &self,
        record_name: &str,
        value: &str,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;

    /// Clear the TXT record `_acme-challenge.{zone}` (all values acme
    /// published for it). Idempotent: clearing a missing record is a
    /// no-op.
    fn clear_txt(&self, record_name: &str)
        -> impl std::future::Future<Output = Result<(), String>> + Send;
}

/// Cloudflare DNS integration - the REST v4 zone API with an
/// API-token bearer (`Zone.DNS:Edit` on the challenge zone only).
///
/// The record name is always a subzone of `SENTIN8_ACME_DNS_ZONE`; the
/// zone id is resolved once (first use) via the zones list filtered by
/// the configured name and cached for the process lifetime.
pub struct CloudflareDns {
    http: reqwest::Client,
    api_token: String,
    zone: String,
    /// The API base URL (provider public endpoint, or the
    /// `SENTIN8_ACME_DNS_API_BASE` override for test rigs/mirrors).
    api_base: String,
    /// Resolved + cached Cloudflare zone id for `zone`.
    zone_id: tokio::sync::RwLock<Option<String>>,
}

impl CloudflareDns {
    /// Build the integration over the config's token + zone. The HTTP
    /// client rides the same hybrid provider posture as the upstream
    /// relay (the platform's exclusive provider cannot reach the public
    /// API endpoint).
    pub fn new(config: &AcmeConfig) -> Result<Self, String> {
        let provider = rustls_graviola::default_provider();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs()
            .map_err(|e| format!("native roots: {e}"))?
        {
            roots.add(cert).map_err(|e| format!("add native cert: {e}"))?;
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
        let api_base = if config.dns_api_base.is_empty() {
            "https://api.cloudflare.com/client/v4".to_string()
        } else {
            config.dns_api_base.clone()
        };
        Ok(Self {
            http,
            api_token: config.dns_api_token.clone(),
            zone: config.dns_zone.clone(),
            api_base,
            zone_id: tokio::sync::RwLock::new(None),
        })
    }

    async fn resolve_zone_id(&self) -> Result<String, String> {
        if let Some(id) = self.zone_id.read().await.clone() {
            return Ok(id);
        }
        let resp = self
            .http
            .get(format!("{}/zones", self.api_base))
            .bearer_auth(&self.api_token)
            .query(&[("name", &self.zone)])
            .send()
            .await
            .map_err(|e| format!("cloudflare zones: {e}"))?;
        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("cloudflare zones parse: {e}"))?;
        if !(200..300).contains(&status.as_u16()) || body["success"] != serde_json::json!(true) {
            let errors = body["errors"].to_string();
            return Err(format!("cloudflare zones {status}: {errors}"));
        }
        let id = body["result"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|z| z["id"].as_str())
            .ok_or_else(|| format!("cloudflare zone '{}' not visible to the token", self.zone))?
            .to_string();
        *self.zone_id.write().await = Some(id.clone());
        Ok(id)
    }

    /// The TXT record name for a DNS-01 challenge over the covered
    /// zone (RFC 8555 §8.4: `_acme-challenge` prefixed to the
    /// authorization identifier - for a wildcard identifier, the
    /// label `_acme-challenge` replaces the `*` label).
    pub fn txt_record_name(covered_zone: &str) -> String {
        format!("_acme-challenge.{covered_zone}")
    }
}

impl DnsProvider for CloudflareDns {
    async fn publish_txt(&self, record_name: &str, value: &str) -> Result<(), String> {
        let zone_id = self.resolve_zone_id().await?;
        // List existing records at the name: an identical live record is
        // a no-op; any other record set is REPLACED (acme owns the
        // challenge name for the order window).
        let list_url = format!("{}/zones/{zone_id}/dns_records", self.api_base);
        let resp = self
            .http
            .get(&list_url)
            .bearer_auth(&self.api_token)
            .query(&[("type", "TXT"), ("name", record_name)])
            .send()
            .await
            .map_err(|e| format!("cloudflare list: {e}"))?;
        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("cloudflare list parse: {e}"))?;
        if !(200..300).contains(&status.as_u16()) || body["success"] != serde_json::json!(true) {
            let errors = body["errors"].to_string();
            return Err(format!("cloudflare list {status}: {errors}"));
        }
        let existing = body["result"].as_array().cloned().unwrap_or_default();
        // A live identical record: idempotent publish.
        if existing.len() == 1
            && existing[0]["content"].as_str() == Some(value)
        {
            return Ok(());
        }
        // Replace any foreign record set at the challenge name.
        for rec in existing {
            let id = rec["id"].as_str().unwrap_or_default().to_string();
            let url = format!("{list_url}/{id}");
            let resp = self
                .http
                .delete(&url)
                .bearer_auth(&self.api_token)
                .send()
                .await
                .map_err(|e| format!("cloudflare delete: {e}"))?;
            if !(200..300).contains(&resp.status().as_u16()) {
                return Err(format!("cloudflare delete {}", resp.status()));
            }
        }
        let resp = self
            .http
            .post(&list_url)
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({
                "type": "TXT",
                "name": record_name,
                "content": value,
                "ttl": 60,
            }))
            .send()
            .await
            .map_err(|e| format!("cloudflare create: {e}"))?;
        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("cloudflare create parse: {e}"))?;
        if !(200..300).contains(&status.as_u16()) || body["success"] != serde_json::json!(true) {
            let errors = body["errors"].to_string();
            return Err(format!("cloudflare create {status}: {errors}"));
        }
        Ok(())
    }

    async fn clear_txt(&self, record_name: &str) -> Result<(), String> {
        let zone_id = self.resolve_zone_id().await?;
        let list_url = format!("{}/zones/{zone_id}/dns_records", self.api_base);
        let resp = self
            .http
            .get(&list_url)
            .bearer_auth(&self.api_token)
            .query(&[("type", "TXT"), ("name", record_name)])
            .send()
            .await
            .map_err(|e| format!("cloudflare list: {e}"))?;
        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("cloudflare list parse: {e}"))?;
        if !(200..300).contains(&status.as_u16()) || body["success"] != serde_json::json!(true) {
            let errors = body["errors"].to_string();
            return Err(format!("cloudflare list {status}: {errors}"));
        }
        for rec in body["result"].as_array().cloned().unwrap_or_default() {
            let id = rec["id"].as_str().unwrap_or_default().to_string();
            let url = format!("{list_url}/{id}");
            let resp = self
                .http
                .delete(&url)
                .bearer_auth(&self.api_token)
                .send()
                .await
                .map_err(|e| format!("cloudflare delete: {e}"))?;
            if !(200..300).contains(&resp.status().as_u16()) {
                return Err(format!("cloudflare delete {}", resp.status()));
            }
        }
        Ok(())
    }
}

/// The record value acme publishes for a DNS-01 challenge: the
/// authorization's key authorization (`token.thumbprint`), per RFC
/// 8555 §8.1.
pub fn dns01_record_value(key_authorization: &str) -> String {
    key_authorization.to_string()
}
