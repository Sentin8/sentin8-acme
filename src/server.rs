// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Acme server — Axum router and server setup.

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;

use crate::acme;
use crate::config::AcmeConfig;
use crate::state::AppState;

/// Build the Axum router: ACME protocol endpoints, CA downloads,
/// client-cert issuance, Shield policy-admin API, RFW admin UI, health.
pub fn build_router(state: Arc<AppState>, counter: sentin8::middleware::RequestCounter) -> Router {
    router_with_shed(state, counter, crate::shed::mint_limiter())
}

/// Build the Axum router (ACME protocol endpoints, CA downloads,
/// client-cert issuance, Shield policy-admin API, RFW admin UI, health)
/// with an EXPLICIT mint limiter — production passes a fresh one; tests
/// inject a pre-loaded limiter to exercise the shed deterministically.
pub fn router_with_shed(
    state: Arc<AppState>,
    counter: sentin8::middleware::RequestCounter,
    limiter: std::sync::Arc<crate::shed::MintLimiter>,
) -> Router {
    Router::new()
        // ── ACME protocol endpoints (RFC 8555) ──
        .route("/acme/directory", get(acme::directory_handler))
        .route("/acme/new-nonce", axum::routing::any(acme::new_nonce))
        .route("/acme/new-account", post(acme::new_account))
        .route("/acme/new-order", post(acme::new_order))
        .route("/acme/authz/{id}", get(acme::get_authz))
        .route("/acme/challenge/{id}", post(acme::challenge_ready))
        .route("/acme/order/{id}", get(acme::get_order))
        .route("/acme/order/{id}/finalize", post(acme::finalize_order))
        .route("/acme/cert/{id}", get(acme::get_cert))
        .route("/acme/revoke-cert", post(acme::revoke_cert))
        // ── HTTP-01 challenge serving (DESIGN §4.3; the proxy's :80
        //    listener forwards here; unauthenticated by RFC 8555 §8.1 —
        //    the token is the capability) ──
        .route(
            "/.well-known/acme-challenge/{token}",
            get(acme::serve_challenge_token),
        )
        // ── CA download (public, no auth) ──
        .route(
            "/v1/internal/schedules/run",
            post(acme::internal_schedules_run),
        )
        .route("/v1/ca/root.crt", get(acme::get_root_ca))
        .route("/v1/ca/intermediate.crt", get(acme::get_intermediate_ca))
        // ── Client-certificate issuance ──
        .route("/v1/client-cert", post(acme::issue_client_cert))
        // ── Admin UI (RFW) ──
        // ── Shield policy-admin API (shared implementation).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<std::sync::Arc<AppState>>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<std::sync::Arc<AppState>>)
                .put(sentin8::shield::admin::put_policy_set::<std::sync::Arc<AppState>>)
                .delete(sentin8::shield::admin::delete_policy_set::<std::sync::Arc<AppState>>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<std::sync::Arc<AppState>>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<std::sync::Arc<AppState>>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<std::sync::Arc<AppState>>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<std::sync::Arc<AppState>>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<std::sync::Arc<AppState>>)
                .put(sentin8::shield::admin::put_relation::<std::sync::Arc<AppState>>)
                .delete(sentin8::shield::admin::delete_relation::<std::sync::Arc<AppState>>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<std::sync::Arc<AppState>>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<std::sync::Arc<AppState>>)
                .put(sentin8::shield::admin::put_attribute::<std::sync::Arc<AppState>>)
                .delete(sentin8::shield::admin::delete_attribute::<std::sync::Arc<AppState>>),
        )
        // ── Policy Studio — RFW renderer aliases (POST-only routes) ──
        .route(
            "/v1/admin/policy-sets",
            post(sentin8::shield::admin::create_policy_set::<std::sync::Arc<AppState>>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/save",
            post(sentin8::shield::admin::save_policy_set::<std::sync::Arc<AppState>>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/{action}",
            post(sentin8::shield::admin::admin_flip_policy_set::<std::sync::Arc<AppState>>),
        )
        .route(
            "/v1/admin/policy-decisions",
            get(sentin8::shield::admin::list_policy_decisions::<std::sync::Arc<AppState>>),
        )
        .route(
            "/v1/admin/relations/{id}/delete",
            post(sentin8::shield::admin::admin_delete_relation::<std::sync::Arc<AppState>>),
        )
        .route(
            "/v1/admin/attributes/{id}/delete",
            post(sentin8::shield::admin::admin_delete_attribute::<std::sync::Arc<AppState>>),
        )
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        .route("/v1/admin/{resource}", get(crate::admin_ui::get_admin_data))
        .route(
            "/v1/admin/certificates/{id}/revoke",
            post(crate::admin_ui::revoke_certificate),
        )
        // ── Health & operations ──
        .route("/v1/health", get(health))
        .with_state(state)
        // ACME-PREF mint admission control: mint endpoints share a bounded
        // queue; overflow answers a clear 503 + Retry-After instead of
        // letting callers time out while the CA signing path saturates.
        .route_layer(axum::middleware::from_fn_with_state(
            limiter,
            crate::shed::mint_shed_layer,
        ))
        // Traffic counter — counts every inbound request (excludes health checks).
        .layer(axum::middleware::from_fn_with_state(
            counter,
            sentin8::middleware::traffic_counter_layer,
        ))
        // Correlation / tenant context / per-request logging
        .layer(axum::middleware::from_fn(
            sentin8::middleware::sentin8_tls_context,
        ))
        .layer(axum::middleware::from_fn(
            sentin8::middleware::request_logging,
        ))
        .layer(axum::middleware::from_fn(
            sentin8::middleware::correlation_id,
        ))
        .layer(TraceLayer::new_for_http())
}

/// Build the router with OpenAPI spec endpoint.
/// Build the router with the OpenAPI spec endpoint merged in.
pub fn build_router_with_openapi(
    state: Arc<AppState>,
    counter: sentin8::middleware::RequestCounter,
) -> Router {
    let app = build_router(state, counter);
    app.merge(sentin8::openapi::openapi_route(
        <crate::openapi::AcmeOpenApi as OpenApi>::openapi(),
    ))
}

async fn health() -> impl axum::response::IntoResponse {
    axum::Json(
        serde_json::json!({"status": "ok", "version": sentin8::build_info::id(), "build": sentin8::build_info::build_hash()}),
    )
}

/// Serve the ACME certificate authority over HTTPS.
///
/// Boot sequence: CA hierarchy (load or generate) → trust-store install →
/// PostgreSQL pool + version check → self-issued bootstrap certificate for
/// the acme hostname (breaks the chicken-and-egg) → Shield boot (one shared
/// engine) → TLS server. Other services fetch their certificates from here.
pub async fn serve(config: AcmeConfig) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("acme listening on {addr}");

    // Generate or load CA hierarchy
    let ca =
        crate::ca::CaHierarchy::ensure(&config).map_err(|e| anyhow::anyhow!("CA init: {e}"))?;

    // Install CA into trust store (best-effort)
    if config.install_trust_store {
        let ca_path = config.root_ca_cert_path();
        match crate::truststore::install_to_os_trust_store(&ca_path) {
            Ok(()) => tracing::info!("Root CA installed into OS trust store"),
            Err(e) => tracing::warn!("OS trust-store install failed: {e} — run acme with root privileges to install automatically"),
        }
        match crate::truststore::install_to_nss(&ca_path) {
            Ok(()) => tracing::info!("Root CA installed into NSS trust store"),
            Err(e) => tracing::warn!("NSS trust-store install failed: {e}"),
        }
        // Also install the Intermediate CA into NSS — Chromium needs it to
        // build the full chain (leaf → intermediate → root) even though the
        // intermediate is served in the TLS handshake. Some Chromium versions
        // don't use the handshake intermediate for trust-building.
        let int_path = config.intermediate_ca_cert_path();
        match crate::truststore::install_intermediate_to_nss(&int_path) {
            Ok(()) => tracing::info!("Intermediate CA installed into NSS trust store"),
            Err(e) => tracing::warn!("NSS intermediate install failed: {e}"),
        }
    }

    let pool = sentin8::config::pg_pool::connect(&config.database_url).await?;
    // Enforce PostgreSQL 18+ (the platform's required database version).
    sentin8::config::Sentin8Config::enforce_postgres_version(&pool)
        .await
        .expect("PostgreSQL 18+ required");
    let valkey_url = config.valkey_url.clone();

    // Self-issue a leaf certificate for the acme's own domain using
    // the CA hierarchy we just loaded/created. This breaks the
    // chicken-and-egg: the acme serves HTTPS, but its cert is signed
    // directly by its own CA — no ACME fetch is needed for its own hostname.
    let acme_hostname = format!("acme.ops.sys.{}", config.sentin8_domain);
    // Include the local IP in the SAN list so that clients connecting via
    // ServiceDiscovery (which resolves to https://{ip}:{port}) can complete
    // the TLS handshake. rcgen auto-detects IP strings → SanType::IpAddress.
    let local_ip = std::env::var("SENTIN8_CAPTAIN_LOCAL_IP").unwrap_or_default();
    let mut sans = vec![acme_hostname.clone()];
    if !local_ip.is_empty() {
        sans.push(local_ip);
    }
    let (cert_pem, key_pem) = ca
        .sign_leaf(&acme_hostname, &sans, config.leaf_cert_days)
        .map_err(|e| anyhow::anyhow!("bootstrap cert signing: {e}"))?;
    tracing::info!(hostname = %acme_hostname, sans = ?sans, "acme: self-issued bootstrap cert");

    // ── Shield boot: acme is a custom-boot binary (no shell serve),
    // so it runs the ONE shared boot helper itself — same four steps
    // the shell runs for every other service. The engine is
    // constructed ONCE and the same Arc is shared with AppState; a
    // second engine would hold an empty cache and deny fail-closed on
    // every admin request.
    let policy_engine = crate::policy::engine();
    crate::policy::boot_full(
        &pool,
        &sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer(),
        "sentin8:acme",
        &policy_engine,
    )
    .await?;

    let state = Arc::new(AppState::with_policy_engine(
        config,
        ca,
        pool.clone(),
        Some(policy_engine),
    ));

    // Traffic metrics — count inbound requests and publish to the same
    // Valkey channel proxy uses (`stat:metrics:tls`) so captain's CALLS
    // column includes acme's direct (non-proxy) traffic.
    let counter = sentin8::middleware::RequestCounter::new();
    sentin8::middleware::spawn_flush_loop(counter.clone(), valkey_url, 10);

    // Leaf-cert renewal (SDD §2.5, foundational-service rule): an
    // internal sweep timer — acme links no scheduler client and makes no
    // cross-service calls. Each pass re-issues certificates inside the
    // T-14d window (the window check lives in the sweep); a failed pass
    // logs and retries on the next tick (never fatal).
    {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(86_400)).await;
                let renewed = crate::acme::sweep(&state).await;
                let _ = renewed; // sweep logs its own outcome
            }
        });
    }

    let app = build_router_with_openapi(state, counter);

    let tls = sentin8::tls::Sentin8Tls::builder()
        .service_identity("sentin8:acme")
        .bootstrap_cert(&acme_hostname, cert_pem, key_pem)
        .build()
        .await?;

    // DBX producer relay (RS §3 D1): drain the LOCAL `acme.outbox` to Bus
    // `POST /v1/produce` (M2M, `sentin8:acme:producer` workload, scope
    // `sentin8:bus:produce`). Fail-open exactly like the shell's step 8b —
    // a Bus outage or DCR failure only disables the relay task; rows
    // persist in the local outbox and the 5s safety poll retries. Acme
    // boots custom (not via the shell), so the relay is spawned here.
    //
    // Bus + auth endpoints are DERIVED from the platform config
    // (`{service}.ops.sys.{SENTIN8_DOMAIN}`) with the same canonical
    // fallbacks the shell boot uses — never a hardcoded IP/port: the bus
    // port is captain-assigned per boot, so a fixed port constant would
    // silently target a dead listener while rows pile up (acme DESIGN §2
    // "Outbox relay — the DBX producer path").
    {
        let relay_pool = pool.clone();
        let derived = sentin8::config::Sentin8Config::from_env();
        let bus_url = std::env::var("SENTIN8_BUS_URL")
            .unwrap_or_else(|_| derived.sentin8_bus_url());
        let auth_issuer = std::env::var("SENTIN8_AUTH_ISSUER")
            .unwrap_or_else(|_| derived.sentin8_auth_issuer());
        tokio::spawn(async move {
            // auth DESIGN §4.3f: the `sentin8:acme`
            // CERTIFICATE is the identity — mint retries while the fleet
            // boots; the relay's own retry loop covers a late identity.
            let bus = loop {
                match sentin8::bus::client::BusClient::for_workload(
                    &bus_url,
                    &auth_issuer,
                    "sentin8:acme",
                )
                .await
                {
                    Ok(c) => break c,
                    Err(e) => {
                        tracing::debug!(error = %e, "acme outbox relay: certificate not ready yet");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                }
            };
            sentin8::bus::outbox::spawn_relay(
                relay_pool,
                std::sync::Arc::new(bus),
                "acme_outbox_changed".to_string(),
            );
        });
    }

    // Serve HTTPS — the cert resolver has the bootstrap cert pre-loaded,
    // so the TLS handshake succeeds immediately for the acme's
    // own hostname. Other services fetch their certs from here over HTTPS.
    tls.serve(&addr, app, "acme").await?;
    Ok(())
}

/// Shared policy-admin surface accessor — the shared
/// handlers extract this service's admin state via [`HasPolicyAdmin`].
impl sentin8::shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
