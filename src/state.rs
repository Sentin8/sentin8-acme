// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Shared application state.

use std::collections::HashMap;
use std::time::SystemTime;
use tokio::sync::RwLock;

use crate::ca::CaHierarchy;
use crate::config::AcmeConfig;
use crate::upstream::UpstreamClient;

/// Shared application state for the ACME server.
pub struct AppState {
    /// Shield (Sentin8:Policy) engine: additional gate for the admin UI paths.
    pub policy: std::sync::Arc<crate::policy::Engine>,
    /// Runtime configuration.
    pub config: AcmeConfig,
    /// The loaded CA hierarchy used for signing.
    pub ca: CaHierarchy,
    /// The upstream ACME relay (external domains, DESIGN §4.2). Built
    /// from the same config; a disabled proxy mode leaves it idle —
    /// every external order is rejected at new-order before it is used.
    pub upstream: UpstreamClient,
    /// Issuer base URL used to build authz/finalize/cert URLs.
    pub issuer: String,
    /// In-memory nonce store (replay protection, RFC 8555 §6.5).
    pub nonces: RwLock<HashMap<String, SystemTime>>,
    /// DB connection pool for the outbox table.
    pub pool: sqlx::PgPool,
    /// Shared Shield policy-admin surface.
    pub admin: sentin8::shield::admin::SharedAdminState,
}

impl AppState {
    /// Build state with a fresh (empty) policy engine — tests only.
    pub fn new(config: AcmeConfig, ca: CaHierarchy, pool: sqlx::PgPool) -> Self {
        Self::with_policy_engine(config, ca, pool, None)
    }

    /// Build state over an EXISTING engine: the boot path loads ONE engine
    /// and the request path must evaluate THAT instance — a second engine
    /// would hold an empty cache and deny fail-closed (fail-closed is
    /// non-negotiable). `engine` is `None` only for tests (`new`).
    /// Build state over an EXISTING engine: the boot path loads ONE engine
    /// and the request path must evaluate THAT instance — a second engine
    /// would hold an empty cache and deny fail-closed (fail-closed is
    /// non-negotiable). `engine` is `None` only for tests (`new`).
    pub fn with_policy_engine(
        config: AcmeConfig,
        ca: CaHierarchy,
        pool: sqlx::PgPool,
        engine: Option<std::sync::Arc<crate::policy::Engine>>,
    ) -> Self {
        // The issuer base URL is used to build authz, finalize, and cert
        // URLs in order/finalize responses. It must use the ACME server's
        // SNI hostname (not `localhost`) so that clients using `.resolve()`
        // to pin the IP while sending the SNI hostname can follow the URLs
        // without hitting a different host. The directory handler still
        // derives URLs from the request's Host header (auto-scale friendly);
        // this is the fallback for order/finalize handlers that don't have
        // access to the request.
        let issuer = format!(
            "https://acme.ops.sys.{}:{}",
            config.sentin8_domain, config.port
        );
        let policy = engine
            .unwrap_or_else(|| std::sync::Arc::new(crate::policy::Engine::new("sentin8:acme")));
        let upstream = UpstreamClient::new(&config)
            .map_err(|e| format!("upstream client init: {e}"))
            .expect("upstream client init");
        Self {
            admin: sentin8::shield::admin::SharedAdminState {
                service: "sentin8:acme".to_string(),
                pool: pool.clone(),
                policy: policy.clone(),
                auth_client: std::sync::Arc::new(config.auth_client.clone()),
            },
            config,
            ca,
            upstream,
            issuer,
            nonces: RwLock::new(HashMap::new()),
            pool,
            policy,
        }
    }
}
