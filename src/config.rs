// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Acme configuration loaded from environment variables.

#![deny(missing_docs)]

use std::env;
use std::path::PathBuf;

/// Acme runtime configuration, sourced from environment variables set by
/// captain (`SENTIN8_ACME_*`).
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// HTTPS listen port.
    pub port: u16,
    /// Data directory (CA material, accounts, orders, certificates).
    pub data_dir: PathBuf,
    /// Root CA validity in days.
    pub root_ca_days: u64,
    /// Intermediate CA validity in days.
    pub intermediate_ca_days: u64,
    /// Leaf certificate validity in days.
    pub leaf_cert_days: u64,
    /// Whether to install the Root CA into OS + NSS trust stores at boot.
    pub install_trust_store: bool,
    /// The platform root domain used to derive the acme hostname.
    pub sentin8_domain: String,
    /// Public ACME provider directory URL for external domains (Let's Encrypt / ZeroSSL).
    /// Empty string = local-only mode (no proxy).
    pub upstream_directory_url: String,
    /// Contact email for the upstream ACME account.
    pub upstream_contact: String,
    /// Optional PEM file pinning the upstream CA chain (external domains).
    /// Empty = verify the upstream against the system roots.
    pub upstream_ca_pem: String,
    /// Operator-declared local-domain suffixes - a domain equal
    /// to or ending with `.{suffix}` classifies LOCAL (platform CA signs
    /// it, HTTP-01 short-circuits). From `SENTIN8_ACME_LOCAL_DOMAINS`
    /// (comma-separated). Dev wildcard zones (`local.sentin8.dev` →
    /// 127.0.0.1) belong here - public CAs refuse loopback-resolving names,
    /// so the upstream path can never succeed for them.
    pub local_domains: Vec<String>,
    /// Operator-declared tier-A allowlist (CERTTIER-1, DESIGN §4.1a) -
    /// the ONLY external identifiers the upstream relay may order.
    /// Entries are exact hostnames (`auth.ibank.example.com`) or
    /// `*.`-prefixed zone wildcards (`*.prod.ibank.example.com`). An
    /// external name NOT on the list is rejected at new-order with the
    /// same 403 as proxy-off, regardless of proxy mode - no name is ever
    /// relayed by fallthrough (invariant 16). From
    /// `SENTIN8_ACME_PUBLIC_HOSTNAMES` (comma-separated).
    pub public_hostnames: Vec<String>,
    /// DNS provider for DNS-01 wildcard challenges (CERTWILD-1, DESIGN
    /// §4.2b). Empty = no provider - a wildcard order is rejected
    /// fail-closed at new-order. From `SENTIN8_ACME_DNS_PROVIDER`
    /// (currently `cloudflare`).
    pub dns_provider: String,
    /// DNS provider API token (CERTWILD-1) - the operator-scoped
    /// credential for TXT record publish/clear. Empty = no provider.
    /// From `SENTIN8_ACME_DNS_API_TOKEN`. Stored by reference in env
    /// conventions; acme reads the literal value from its own
    /// operator-controlled environment (the same posture as
    /// `SENTIN8_ACME_UPSTREAM_CONTACT`).
    pub dns_api_token: String,
    /// DNS zone the provider token is scoped to (CERTWILD-1) - e.g.
    /// `ibank.example.com`. The `_acme-challenge` TXT record publishes
    /// under `{zone}` (or its subzone, derived from the identifier).
    /// From `SENTIN8_ACME_DNS_ZONE`.
    pub dns_zone: String,
    /// DNS provider API base URL (CERTWILD-1). Defaults to the
    /// provider's public endpoint (`cloudflare` →
    /// `https://api.cloudflare.com/client/v4`); the override exists for
    /// test rigs and API mirrors. From `SENTIN8_ACME_DNS_API_BASE`.
    pub dns_api_base: String,
    /// Database URL for the outbox table.
    pub database_url: String,
    /// Bus base URL for event publication.
    pub sentin8_bus_url: String,
    /// Bus stream family for Acme events (default `"acme"`).
    pub stream_family: String,
    /// Valkey URL for publishing traffic metrics to `stat:metrics:tls`
    /// (same channel proxy uses). Empty = metrics flush disabled.
    pub valkey_url: String,
    /// Auth client config for admin token verification.
    pub sentin8_auth_url: String,
    /// Auth client for token verification.
    pub auth_client: sentin8::auth::client::Client,
}

impl AcmeConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let sentin8_domain = env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "local.sentin8.dev".into());
        // FHS: /var/lib/sentin8/tls (prod), or SENTIN8_ACME_DATA_DIR override, or
        // $HOME/.sentin8/acme (dev fallback for backward compat).
        //
        // PQCA-1: the data dir is PER-PQ-MODE (`{base}/{pq_mode}`) - the
        // CA hierarchy, accounts, orders, and certificates live under
        // the mode's own directory (acme DESIGN "Filesystem layout"). A
        // mode flip populates the other directory from scratch; a leaf
        // minted for another posture is unreachable by construction. Host
        // and appliance share the base mount and the same operator .env,
        // so both planes resolve the SAME mode dir.
        let data_dir = {
            let base = env::var("SENTIN8_ACME_DATA_DIR")
                .unwrap_or_else(|_| sentin8::config::tls_dir());
            sentin8::config::acme_data_dir_mode(&base)
        };
        Self {
            port: env::var("SENTIN8_ACME_PORT")
                .expect("SENTIN8_ACME_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_ACME_PORT must be a valid u16"),
            data_dir: PathBuf::from(data_dir),
            root_ca_days: env::var("SENTIN8_ACME_ROOT_CA_DAYS")
                .unwrap_or("3650".into())
                .parse()
                .unwrap_or(3650),
            intermediate_ca_days: env::var("SENTIN8_ACME_INTERMEDIATE_CA_DAYS")
                .unwrap_or("1825".into())
                .parse()
                .unwrap_or(1825),
            leaf_cert_days: env::var("SENTIN8_ACME_LEAF_CERT_DAYS")
                .unwrap_or("90".into())
                .parse()
                .unwrap_or(90),
            install_trust_store: env::var("SENTIN8_ACME_INSTALL_TRUST_STORE")
                .map(|v| v != "false")
                .unwrap_or(true),
            sentin8_domain,
            upstream_directory_url: env::var("SENTIN8_ACME_UPSTREAM_DIRECTORY_URL")
                .unwrap_or_default(),
            upstream_contact: env::var("SENTIN8_ACME_UPSTREAM_CONTACT")
                .unwrap_or_else(|_| "a@m.n".into()),
            upstream_ca_pem: env::var("SENTIN8_ACME_UPSTREAM_CA_PEM").unwrap_or_default(),
            local_domains: env::var("SENTIN8_ACME_LOCAL_DOMAINS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            public_hostnames: env::var("SENTIN8_ACME_PUBLIC_HOSTNAMES")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            dns_provider: env::var("SENTIN8_ACME_DNS_PROVIDER")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase(),
            dns_api_token: env::var("SENTIN8_ACME_DNS_API_TOKEN").unwrap_or_default(),
            dns_zone: env::var("SENTIN8_ACME_DNS_ZONE")
                .unwrap_or_default()
                .trim()
                .trim_matches('.')
                .to_ascii_lowercase(),
            dns_api_base: env::var("SENTIN8_ACME_DNS_API_BASE")
                .unwrap_or_default()
                .trim()
                .trim_end_matches('/')
                .to_string(),
            // (DESIGN §3): explicit override → else the
            // DERIVED identity DSN. The legacy operator `DATABASE_URL` is
            // NEVER a fallback: under the superuser role the unqualified
            // outbox INSERT resolves through the operator search_path
            // (`auth, sys, …`) and lands in another service's
            // `auth.outbox` (DESIGN §8 invariant 7 - no silent shared-role
            // fallback).
            database_url: env::var("SENTIN8_ACME_DATABASE_URL")
                .unwrap_or_else(|_| sentin8::config::service_database_url("sentin8:acme")),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL")
                .unwrap_or_else(|_| sentin8::config::Sentin8Config::from_env().sentin8_bus_url()),
            stream_family: env::var("SENTIN8_ACME_STREAM_FAMILY").unwrap_or_else(|_| "acme".into()),
            valkey_url: env::var("SENTIN8_ACME_VALKEY_URL").unwrap_or_else(|_| {
                // override chain → else the plane-derived URL.
                std::env::var("VALKEY_URL")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(sentin8::config::service_valkey_url)
            }),
            sentin8_auth_url: env::var("SENTIN8_AUTH_URL").unwrap_or_else(|_| {
                sentin8::config::Sentin8Config::from_env()
                    .sentin8_auth_url()
                    .to_string()
            }),
            auth_client: sentin8::auth::client::Client::new(sentin8::auth::client::ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER").unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer()
                }),
                ..Default::default()
            }),
        }
    }

    /// Directory holding the CA hierarchy material.
    pub fn ca_dir(&self) -> PathBuf {
        self.data_dir.join("ca")
    }

    /// Path of the Root CA certificate.
    pub fn root_ca_cert_path(&self) -> PathBuf {
        self.ca_dir().join("root-ca.crt")
    }

    /// Path of the Root CA private key (0600).
    pub fn root_ca_key_path(&self) -> PathBuf {
        self.ca_dir().join("root-ca.key")
    }

    /// Path of the Intermediate CA certificate.
    pub fn intermediate_ca_cert_path(&self) -> PathBuf {
        self.ca_dir().join("intermediate-ca.crt")
    }

    /// Path of the Intermediate CA private key (0600).
    /// Per-PQ-mode (same as the cert - see `intermediate_ca_cert_path`).
    pub fn intermediate_ca_key_path(&self) -> PathBuf {
        self.intermediate_ca_cert_path()
            .with_file_name("intermediate-ca.key")
    }

    /// Directory of ACME account records.
    pub fn accounts_dir(&self) -> PathBuf {
        self.data_dir.join("accounts")
    }

    /// Directory of order and authorization records.
    pub fn orders_dir(&self) -> PathBuf {
        self.data_dir.join("orders")
    }

    /// Directory of issued certificates.
    pub fn certs_dir(&self) -> PathBuf {
        self.data_dir.join("certificates")
    }

    /// Directory of one certificate (cert, key, metadata).
    pub fn cert_dir(&self, cert_id: &str) -> PathBuf {
        self.certs_dir().join(cert_id)
    }

    /// Certificate PEM path for a cert id.
    pub fn cert_path(&self, cert_id: &str) -> PathBuf {
        self.cert_dir(cert_id).join("cert.pem")
    }

    /// Private key PEM path for a cert id.
    pub fn cert_key_path(&self, cert_id: &str) -> PathBuf {
        self.cert_dir(cert_id).join("key.pem")
    }

    /// Issuance metadata path for a cert id.
    pub fn cert_meta_path(&self, cert_id: &str) -> PathBuf {
        self.cert_dir(cert_id).join("metadata.json")
    }

    /// Path to the upstream ACME account file (for external domain proxying).
    pub fn upstream_account_path(&self) -> PathBuf {
        self.data_dir.join("upstream-account.json")
    }

    /// Whether ACME proxy mode is enabled (non-empty upstream URL).
    pub fn proxy_mode_enabled(&self) -> bool {
        !self.upstream_directory_url.is_empty()
    }

    /// Whether the identifier is on the tier-A allowlist (CERTTIER-1,
    /// DESIGN §4.1a) - an exact-hostname entry matches itself, a
    /// `*.{zone}` entry matches every single label under the zone
    /// (RFC 8555 §7.1.3 wildcard semantics: exactly one label).
    /// A plain-hostname identifier also matches a wildcard entry
    /// (the covered name orders the wildcard's exact form); a
    /// `*.{zone}` identifier matches the wildcard entry itself.
    pub fn is_public_hostname_allowed(&self, identifier: &str) -> bool {
        let id = identifier.to_ascii_lowercase();
        self.public_hostnames.iter().any(|entry| {
            let entry = entry.to_ascii_lowercase();
            if let Some(entry_zone) = entry.strip_prefix("*.") {
                // Wildcard entry: the wildcard identifier itself, or a
                // covered name with exactly ONE label beneath the zone -
                // `a.{zone}` matches, `a.b.{zone}` does not, `{zone}`
                // does not (RFC 8555 §7.1.3 wildcard semantics).
                if id == entry {
                    return true;
                }
                match id.split_once('.') {
                    Some((label, rest)) => !label.is_empty() && rest == entry_zone,
                    None => false,
                }
            } else {
                entry == id
            }
        })
    }

    /// Whether DNS-01 is required for the identifier shape (CERTWILD-1,
    /// DESIGN §4.2b): a wildcard identifier cannot be validated by
    /// HTTP-01 (RFC 8555 §8.4 - the challenge validates the covered
    /// name's HTTP endpoint, which does not exist for `*`), so the
    /// shape routes to DNS-01. The selection is by identifier shape,
    /// never an operator knob.
    pub fn requires_dns01(&self, identifier: &str) -> bool {
        identifier.starts_with("*.")
    }

    /// Whether a DNS provider profile is configured for DNS-01 (an
    /// empty provider, token, OR zone disables the path - each is
    /// necessary; a partial profile is fail-closed as if absent).
    pub fn dns01_configured(&self) -> bool {
        !self.dns_provider.is_empty()
            && !self.dns_api_token.is_empty()
            && !self.dns_zone.is_empty()
    }

    /// Create the data directory layout (ca, accounts, orders, certificates).
    pub fn init_dirs(&self) -> Result<(), String> {
        for sub in ["ca", "accounts", "orders", "certificates"] {
            std::fs::create_dir_all(self.data_dir.join(sub)).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}
