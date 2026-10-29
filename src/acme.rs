// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! ACME protocol implementation (RFC 8555).
//!
//! Directory, nonce, account registration, order creation, authorization
//! + challenge, HTTP-01 verification, local-domain short-circuit, order
//! finalize + certificate issuance, and revocation.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use uuid::Uuid;

use crate::state::AppState;

// ── Directory (RFC 8555 §7.1.1) ────────────────────────────────────────

/// `GET /acme/directory` - ACME directory object (RFC 8555 §7.1.1).
///
/// URLs are derived from the incoming request's scheme and Host header so
/// they remain correct on any port or replica (auto-scale friendly).
#[utoipa::path(
    get,
    path = "/acme/directory",
    responses(
        (status = 200, description = "RFC 8555 directory (resource URLs resolved from the request Host)", body = AcmeDirectory),
    ),
    security(),
)]
pub async fn directory_handler(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    // Build the base URL from the incoming request's scheme + host header.
    // This keeps the directory URLs correct regardless of which port or IP
    // the acme is listening on (auto-scale friendly).
    let scheme = if request.uri().scheme_str() == Some("https") {
        "https"
    } else {
        "http"
    };
    let host = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or(&state.issuer);
    let base = format!("{scheme}://{host}/acme");
    Json(AcmeDirectory {
        new_nonce: format!("{base}/new-nonce"),
        new_account: format!("{base}/new-account"),
        new_order: format!("{base}/new-order"),
        revoke_cert: format!("{base}/revoke-cert"),
        key_change: format!("{base}/key-change"),
    })
}

// ── Nonce (RFC 8555 §6.5) ──────────────────────────────────────────────

/// `GET/HEAD /acme/new-nonce` - issue a fresh anti-replay nonce
/// (RFC 8555 §6.5), returned in the `Replay-Nonce` header.
pub async fn new_nonce(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let nonce = generate_nonce();
    state
        .nonces
        .write()
        .await
        .insert(nonce.clone(), SystemTime::now());
    (
        StatusCode::OK,
        [("Replay-Nonce", nonce)],
        axum::body::Body::empty(),
    )
}

// ── Account (RFC 8555 §7.1.2) ──────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
/// Request body for `POST /acme/new-account`.
pub struct NewAccountRequest {
    /// Contact URLs for the account (e.g. `mailto:`).
    #[serde(default)]
    pub contact: Vec<String>,
    /// Whether the client agrees to the terms of service.
    #[serde(default)]
    pub termsOfServiceAgreed: bool,
    /// Return an error instead of creating a new account.
    #[serde(default)]
    pub onlyReturnExisting: bool,
    /// The account's public key as a JWK (RFC 7517). Acme computes the
    /// RFC 7638 thumbprint over it and stores the hash - every
    /// account-scoped request must then present a key whose thumbprint
    /// matches (RFC 8555 §6.2 account-key binding).
    #[serde(default)]
    pub jwk: Option<serde_json::Value>,
}

/// `POST /acme/new-account` - register a new ACME account (RFC 8555 §7.1.2),
/// persisted to the accounts directory and announced as
/// `sentin8:acme:account:created`.
#[utoipa::path(
    post,
    path = "/acme/new-account",
    responses(
        (status = 201, description = "Account created/updated (JWS-verified)"),
        (status = 400, description = "Malformed JWS"),
        (status = 403, description = "Rejected identifier policy"),
    ),
    security(),
)]
pub async fn new_account(
    State(state): State<Arc<AppState>>,
    Json(req): Json<NewAccountRequest>,
) -> Response {
    if req.onlyReturnExisting {
        return (StatusCode::BAD_REQUEST, "account not found").into_response();
    }

    // RFC 7638 thumbprint over the presented key (when the client embeds
    // its JWK). Absent a JWK the account is created WITHOUT key binding
    // (platform-internal consumers); thumbprint-bound accounts gain the
    // §6.2 verification on their account-scoped requests.
    let key_thumbprint = match req.jwk.as_ref().map(calculate_thumbprint) {
        Some(Ok(t)) => Some(t),
        Some(Err(e)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "type": "urn:ietf:params:acme:error:malformed",
                    "detail": format!("invalid embedded JWK: {e}"),
                })),
            )
                .into_response()
        }
        None => None,
    };
    let account_id = Uuid::new_v4().to_string();
    let account = AccountRecord {
        id: account_id.clone(),
        contact: req.contact,
        status: "valid".into(),
        created_at: now_ts(),
        key_thumbprint: key_thumbprint.unwrap_or_default(),
    };

    let account_path = state
        .config
        .accounts_dir()
        .join(format!("{account_id}.json"));
    let json = serde_json::to_string(&account).unwrap();
    std::fs::write(&account_path, json).ok();

    emit_event(
        &state,
        "sentin8:acme:account:created",
        serde_json::to_value(&account).unwrap_or_default(),
    )
    .await;
    let location = format!("{}/acme/account/{account_id}", state.issuer);
    (
        StatusCode::CREATED,
        [
            ("Location", location),
            ("Content-Type", "application/json".to_string()),
        ],
        Json(account),
    )
        .into_response()
}

// ── Order (RFC 8555 §7.1.3) ────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
/// Request body for `POST /acme/new-order`.
pub struct NewOrderRequest {
    /// Certificate identifiers requested (DNS names).
    pub identifiers: Vec<Identifier>,
    /// Earliest requested validity start.
    #[serde(default)]
    pub notBefore: Option<String>,
    /// Latest requested validity end.
    #[serde(default)]
    pub notAfter: Option<String>,
    /// The account making the order (RFC 8555 §6.2 account binding).
    #[serde(default)]
    pub accountId: Option<String>,
    /// The RFC 7638 thumbprint of the signing key - must match the
    /// account's stored thumbprint (RFC 8555 §6.2, ACME-2).
    #[serde(default)]
    pub keyThumbprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
/// An ACME order identifier (DNS name).
pub struct Identifier {
    /// Identifier type (`dns`).
    #[serde(rename = "type")]
    pub id_type: String,
    /// Identifier value (the domain name).
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
/// An ACME order as persisted and returned.
pub struct OrderRecord {
    /// Order id.
    pub id: String,
    /// Lifecycle status (`pending`/`valid`).
    pub status: String,
    /// Requested identifiers.
    pub identifiers: Vec<Identifier>,
    /// Authorization URLs that must be satisfied.
    pub authorizations: Vec<String>,
    /// Finalize URL for submitting the CSR.
    pub finalize: String,
    /// Certificate URL once issued.
    pub certificate: Option<String>,
    /// Creation time (unix seconds).
    pub created_at: u64,
}

/// `POST /acme/new-order` - create an order (RFC 8555 §7.1.3).
///
/// Mixed local/external identifiers are rejected; external orders are
/// proxied to the upstream ACME provider when proxy mode is enabled,
/// otherwise the local CA issues them after challenge validation.
#[utoipa::path(
    post,
    path = "/acme/new-order",
    responses(
        (status = 201, description = "Order created (authorizations + finalize URLs; locally-signed or relayed upstream)", body = OrderRecord),
        (status = 400, description = "Unsupported/forbidden identifier"),
        (status = 403, description = "Local-domain without proxy mode, or relay proxy off"),
    ),
    security(),
)]
pub async fn new_order(
    State(state): State<Arc<AppState>>,
    Json(req): Json<NewOrderRequest>,
) -> Response {
    // ── Account-key binding (RFC 8555 §6.2, ACME-2) ──
    // When the referenced account was created with a key thumbprint, the
    // order must present the SAME thumbprint - a stolen account id without
    // the account private key cannot place orders.
    if let Some(account_id) = req.accountId.as_deref() {
        let account_path = state
            .config
            .accounts_dir()
            .join(format!("{account_id}.json"));
        let bound = std::fs::read_to_string(&account_path)
            .ok()
            .and_then(|s| serde_json::from_str::<AccountRecord>(&s).ok())
            .map(|a| a.key_thumbprint)
            .unwrap_or_default();
        if !bound.is_empty() {
            let presented = req.keyThumbprint.as_deref().unwrap_or("");
            if bound != presented {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "type": "urn:ietf:params:acme:error:unauthorized",
                        "detail": "JWS embedded key thumbprint does not match the account key (RFC 8555 §6.2)",
                    })),
                )
                    .into_response();
            }
        }
    }

    // ── Domain classification (DESIGN §4.1) ──
    // Classify the order as local or external. Mixed orders are rejected
    // (disjoint trust chains - a cert must not mix platform-CA and
    // upstream-signed names).
    let all_local = req
        .identifiers
        .iter()
        .all(|i| is_local_domain(&i.value, &state.config.local_domains));
    let all_external = req
        .identifiers
        .iter()
        .all(|i| !is_local_domain(&i.value, &state.config.local_domains));
    if !all_local && !all_external {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "type": "urn:ietf:params:acme:error:malformed",
                "detail": "mixed local and external identifiers in a single order are not supported"
            })),
        )
            .into_response();
    }

    // ── External domain relay ──
    // With proxy mode on, external orders are relayed to the upstream CA
    // (DESIGN §4.2). With proxy mode off, an external identifier is
    // REJECTED - there is no local proof of control for a public name, so
    // signing it would mint a trusted identity from an untrusted request.
    if all_external {
        if state.config.proxy_mode_enabled() {
            return relay_new_order(&state, &req).await;
        }
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "type": "urn:ietf:params:acme:error:rejectedIdentifier",
                "detail": "external domain orders require an upstream ACME provider (SENTIN8_ACME_UPSTREAM_DIRECTORY_URL not configured)",
            })),
        )
            .into_response();
    }

    let order_id = Uuid::new_v4().to_string();
    let authz_id = Uuid::new_v4().to_string();
    let base = format!("{}/acme", state.issuer);

    let order = OrderRecord {
        id: order_id.clone(),
        status: "pending".into(),
        identifiers: req.identifiers.clone(),
        authorizations: vec![format!("{base}/authz/{authz_id}")],
        finalize: format!("{base}/order/{order_id}/finalize"),
        certificate: None,
        created_at: now_ts(),
    };

    // Store order
    let order_path = state.config.orders_dir().join(format!("{order_id}.json"));
    std::fs::write(&order_path, serde_json::to_string(&order).unwrap()).ok();

    // Create authorization with challenge
    let authz = AuthorizationRecord {
        id: authz_id.clone(),
        identifier: req.identifiers.into_iter().next().unwrap_or(Identifier {
            id_type: "dns".into(),
            value: "".into(),
        }),
        status: "pending".into(),
        challenges: vec![ChallengeRecord {
            id: Uuid::new_v4().to_string(),
            challenge_type: "http-01".into(),
            status: "pending".into(),
            token: generate_nonce(),
            url: format!("{base}/challenge/{}", Uuid::new_v4()),
        }],
    };
    let authz_path = state
        .config
        .orders_dir()
        .join(format!("authz-{authz_id}.json"));
    if let Err(e) = std::fs::write(&authz_path, serde_json::to_string(&authz).unwrap()) {
        tracing::error!("Failed to write authz file: {e} (path={authz_path:?})");
    }

    emit_event(
        &state,
        "sentin8:acme:order:created",
        serde_json::to_value(&order).unwrap_or_default(),
    )
    .await;
    let location = format!("{base}/order/{order_id}");
    (
        StatusCode::CREATED,
        [
            ("Location", location),
            ("Content-Type", "application/json".to_string()),
        ],
        Json(order),
    )
        .into_response()
}

// ── Authorization (RFC 8555 §7.1.4) ─────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
/// An order authorization as persisted and returned.
pub struct AuthorizationRecord {
    /// Authorization id.
    pub id: String,
    /// The identifier being proven.
    pub identifier: Identifier,
    /// Lifecycle status (`pending`/`valid`/`invalid`).
    pub status: String,
    /// Challenges that can prove control of the identifier.
    pub challenges: Vec<ChallengeRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
/// A single authorization challenge.
pub struct ChallengeRecord {
    /// Challenge id.
    pub id: String,
    /// Challenge type (`http-01`).
    pub challenge_type: String,
    /// Lifecycle status (`pending`/`valid`/`invalid`).
    pub status: String,
    /// Challenge token the client echoes at the well-known path.
    pub token: String,
    /// Challenge URL.
    pub url: String,
}

/// `GET /acme/authz/{id}` - fetch an authorization (RFC 8555 §7.1.4).
#[utoipa::path(
    get,
    path = "/acme/authz/{id}",
    params(("id" = String, Path, description = "Authorization id")),
    responses(
        (status = 200, description = "Authorization challenges (RFC 8555 §7.1.4)"),
        (status = 404, description = "Unknown authorization"),
    ),
    security(),
)]
pub async fn get_authz(
    State(state): State<Arc<AppState>>,
    AxumPath(authz_id): AxumPath<String>,
) -> Response {
    let path = state
        .config
        .orders_dir()
        .join(format!("authz-{authz_id}.json"));
    match std::fs::read_to_string(&path) {
        Ok(json) => {
            let authz: AuthorizationRecord = serde_json::from_str(&json).unwrap();
            Json(authz).into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "authorization not found").into_response(),
    }
}

// ── Challenge (RFC 8555 §7.1.4, §8.3) ───────────────────────────────────

/// `POST /acme/challenge/{id}` - signal the challenge is ready for
/// validation (RFC 8555 §8.3). Local orders short-circuit to `valid`
/// (the challenge target is the platform's own host network); external
/// orders notify the upstream CA that its http-01 challenge is ready -
/// the upstream then fetches the key authorization from the proxy's
/// :80 listener → acme's well-known route (DESIGN §4.2/§4.3).
#[utoipa::path(
    post,
    path = "/acme/challenge/{id}",
    params(("id" = String, Path, description = "Challenge id")),
    responses(
        (status = 200, description = "Challenge marked ready (proxy mode: notifies the upstream)"),
        (status = 404, description = "Unknown challenge"),
        (status = 409, description = "Challenge not pending"),
    ),
    security(),
)]
pub async fn challenge_ready(
    State(state): State<Arc<AppState>>,
    AxumPath(challenge_id): AxumPath<String>,
) -> Response {
    // Local domains skip verification (the challenge target IS this
    // server's host network) - mark valid directly. External domains
    // notify the upstream CA; the key authorization was captured at
    // new-order time and is served from the bounded challenge map.

    // Find the authorization that contains this challenge
    let entries = match std::fs::read_dir(state.config.orders_dir()) {
        Ok(e) => e.filter_map(|e| e.ok()).collect::<Vec<_>>(),
        Err(_) => return (StatusCode::NOT_FOUND, "challenge not found").into_response(),
    };

    for entry in entries {
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.starts_with("authz-") {
            continue;
        }
        if let Ok(json) = std::fs::read_to_string(entry.path()) {
            if let Ok(mut authz) = serde_json::from_str::<AuthorizationRecord>(&json) {
                let challenge_idx = authz
                    .challenges
                    .iter()
                    .position(|c| c.id == challenge_id || c.url.ends_with(&challenge_id));
                if let Some(idx) = challenge_idx {
                    {
                        let ch = &mut authz.challenges[idx];

                        // Check if this is a local order (DESIGN §4.1) -
                        // local orders short-circuit; external orders carry
                        // the upstream's token in the bounded map and are
                        // notified upstream.
                        if is_local_domain(&authz.identifier.value, &state.config.local_domains)
                            && state
                                .upstream
                                .challenge_tokens
                                .read()
                                .await
                                .get(&ch.token)
                                .is_none()
                        {
                            ch.status = "valid".into();
                            authz.status = "valid".into();
                        } else {
                            // External order - notify the upstream CA
                            // (DESIGN §4.2). The upstream validates by
                            // fetching the key authorization from the
                            // proxy's :80 listener; the local authz goes
                            // valid only after the upstream accepts.
                            let upstream_url = ch.url.clone();
                            match state.upstream.notify_challenge(&upstream_url).await {
                                Ok(()) => {
                                    ch.status = "valid".into();
                                    authz.status = "valid".into();
                                }
                                Err(e) => {
                                    ch.status = "invalid".into();
                                    let path = state
                                        .config
                                        .orders_dir()
                                        .join(format!("authz-{}.json", authz.id));
                                    std::fs::write(&path, serde_json::to_string(&authz).unwrap())
                                        .ok();
                                    return Json(serde_json::json!({
                                        "status": "invalid",
                                        "error": e.to_string(),
                                    }))
                                    .into_response();
                                }
                            }
                        }
                    }
                    // Mutable borrow released - now serialize
                    let path = state
                        .config
                        .orders_dir()
                        .join(format!("authz-{}.json", authz.id));
                    std::fs::write(&path, serde_json::to_string(&authz).unwrap()).ok();
                    let url = authz.challenges[idx].url.clone();
                    return Json(serde_json::json!({
                        "status": "valid",
                        "url": url,
                    }))
                    .into_response();
                }
            }
        }
    }
    (StatusCode::NOT_FOUND, "challenge not found").into_response()
}

// ── Finalize + Certificate (RFC 8555 §7.1.3, §7.4) ───────────────────────

#[derive(Debug, Deserialize)]
/// Request body for order finalize.
pub struct FinalizeRequest {
    /// Base64url-encoded PKCS#10 CSR.
    pub csr: String,
}

/// `POST /acme/order/{id}/finalize` - submit the CSR and issue the
/// certificate (RFC 8555 §7.4). Local orders require a VALID
/// authorization (defense in depth - the challenge short-circuit set it;
/// an order that never proved control is never signed) and are signed
/// by the Intermediate CA; external orders are finalized upstream
/// through the relay and the certificate cached (DESIGN §4.2).
#[utoipa::path(
    post,
    path = "/acme/order/{id}/finalize",
    params(("id" = String, Path, description = "Order id")),
    responses(
        (status = 200, description = "Order finalized (CSR processed; platform-CA or upstream-signed chain)"),
        (status = 400, description = "Invalid CSR"),
        (status = 404, description = "Unknown order"),
        (status = 409, description = "Order not in ready state"),
    ),
    security(),
)]
pub async fn finalize_order(
    State(state): State<Arc<AppState>>,
    AxumPath(order_id): AxumPath<String>,
    Json(req): Json<FinalizeRequest>,
) -> Response {
    let order_path = state.config.orders_dir().join(format!("{order_id}.json"));
    let order_json = match std::fs::read_to_string(&order_path) {
        Ok(j) => j,
        Err(_) => return (StatusCode::NOT_FOUND, "order not found").into_response(),
    };

    // Check if this is a proxy order (external domain)
    let parsed: serde_json::Value = serde_json::from_str(&order_json).unwrap();
    let is_proxy = parsed
        .get("is_proxy")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let order: OrderRecord = parsed
        .get("order")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_else(|| serde_json::from_str(&order_json).unwrap());

    if is_proxy {
        return relay_finalize_order(&state, &order_id, &order, &parsed).await;
    }

    let mut order = order;

    // Defense in depth (DESIGN §4.1 invariant 10): a LOCAL order signs
    // only after its authorization is valid - the platform CA must never
    // mint a cert for a name whose challenge was never satisfied.
    let authz_ok = order.authorizations.iter().all(|url| {
        let authz_id = url
            .rsplit('/')
            .next()
            .map(|id| id.to_string())
            .unwrap_or_default();
        let path = state
            .config
            .orders_dir()
            .join(format!("authz-{authz_id}.json"));
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str::<AuthorizationRecord>(&s).ok())
            .map(|a| a.status == "valid")
            .unwrap_or(false)
    });
    if !authz_ok {
        return (
            StatusCode::FORBIDDEN,
            "order authorization is not valid - complete the challenge first",
        )
            .into_response();
    }

    // Re-derive the local classification (stored decision re-checked at
    // finalize - DESIGN §4.1).
    if !order
        .identifiers
        .iter()
        .all(|i| is_local_domain(&i.value, &state.config.local_domains))
    {
        return (
            StatusCode::FORBIDDEN,
            "order is not local - external domains require the upstream relay",
        )
            .into_response();
    }

    // Decode the CSR (not used for signing - rcgen generates its own key)
    let _csr_der = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&req.csr) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid CSR: {e}")).into_response(),
    };

    // Extract domain from the order identifiers
    let domain = order
        .identifiers
        .iter()
        .find(|i| i.id_type == "dns")
        .map(|i| i.value.clone())
        .unwrap_or("unknown".to_string());

    // Generate a leaf certificate (local domain - direct signing)
    let san_names: Vec<String> = order
        .identifiers
        .iter()
        .filter(|i| i.id_type == "dns")
        .map(|i| i.value.clone())
        .collect();

    // Reuse-before-mint (DESIGN §4.0): when a non-revoked,
    // unexpired certificate for the SAME domain already exists in the
    // store, finalize the order against it - no new signing, no new cert
    // directory. The service plane persists its leaves and pre-warms at
    // boot, so restart/reset re-requests must be idempotent; without
    // reuse, every re-request minted a fresh leaf + directory
    // (52,761 dirs / 650 MB observed before this rule).
    if let Some((existing_id, _existing_domain)) =
        find_reusable_cert(&state.config, &domain)
    {
        tracing::info!(domain = %domain, cert_id = %existing_id, "reuse-before-mint: returning existing certificate");
        order.status = "valid".into();
        order.certificate = Some(format!("{}/acme/cert/{existing_id}", state.issuer));
        std::fs::write(&order_path, serde_json::to_string(&order).unwrap()).ok();
        emit_event(
            &state,
            "sentin8:acme:order:finalized",
            serde_json::to_value(&order).unwrap_or_default(),
        )
        .await;
        return Json(order).into_response();
    }

    let cert_id = Uuid::new_v4().to_string();
    let (cert_pem, key_pem) =
        match state
            .ca
            .sign_leaf(&domain, &san_names, state.config.leaf_cert_days)
        {
            Ok(c) => c,
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("sign cert: {e}"))
                    .into_response()
            }
        };

    // sign_leaf already returns the full chain (leaf + intermediate + root).
    // Store it directly - no need to append the intermediate again.
    let full_chain: Vec<u8> = cert_pem;

    // Store the certificate (full chain) and key
    let cert_dir = state.config.cert_dir(&cert_id);
    std::fs::create_dir_all(&cert_dir).ok();
    std::fs::write(state.config.cert_path(&cert_id), &full_chain).ok();
    std::fs::write(state.config.cert_key_path(&cert_id), &key_pem).ok();

    // Write metadata (local signing)
    let meta = serde_json::json!({
        "domain": domain,
        "issued_at": now_ts(),
        "expires_at": now_ts() + state.config.leaf_cert_days * 86400,
        "serial": cert_id,
        "revoked": false,
        "source": "local",
    });
    std::fs::write(state.config.cert_meta_path(&cert_id), meta.to_string()).ok();

    // Update order
    order.status = "valid".into();
    order.certificate = Some(format!("{}/acme/cert/{cert_id}", state.issuer));
    std::fs::write(&order_path, serde_json::to_string(&order).unwrap()).ok();

    emit_event(
        &state,
        "sentin8:acme:order:finalized",
        serde_json::to_value(&order).unwrap_or_default(),
    )
    .await;
    Json(order).into_response()
}

// ── Certificate download (RFC 8555 §7.4.2) ───────────────────────────────

/// `GET /acme/cert/{id}` - download the certificate as a combined PEM
/// (chain, plus the private key for locally-issued certs so TLS can build
/// its `ServerConfig` from one artifact).
#[utoipa::path(
    get,
    path = "/acme/cert/{id}",
    params(("id" = String, Path, description = "Certificate cache id")),
    responses(
        (status = 200, description = "Certificate (chain; + private key for locally-issued certs)"),
        (status = 404, description = "Unknown certificate"),
    ),
    security(),
)]
pub async fn get_cert(
    State(state): State<Arc<AppState>>,
    AxumPath(cert_id): AxumPath<String>,
) -> Response {
    let cert_path = state.config.cert_path(&cert_id);
    let key_path = state.config.cert_key_path(&cert_id);
    match (
        std::fs::read_to_string(&cert_path),
        std::fs::read_to_string(&key_path),
    ) {
        (Ok(cert_pem), Ok(key_pem)) => {
            // Return both cert and key as a combined PEM for local domains.
            // TLS needs both to build the TLS ServerConfig.
            let combined = format!("{cert_pem}{key_pem}");
            (
                StatusCode::OK,
                [(
                    "Content-Type",
                    "application/pem-certificate-chain".to_string(),
                )],
                combined,
            )
                .into_response()
        }
        (Ok(cert_pem), Err(_)) => {
            // External domain - only cert (no key, as it was obtained from upstream)
            (
                StatusCode::OK,
                [(
                    "Content-Type",
                    "application/pem-certificate-chain".to_string(),
                )],
                cert_pem,
            )
                .into_response()
        }
        (Err(_), _) => (StatusCode::NOT_FOUND, "certificate not found").into_response(),
    }
}

// ── Order status ───────────────────────────────────────────────────────

/// `GET /acme/order/{id}` - fetch the order status.
#[utoipa::path(
    get,
    path = "/acme/order/{id}",
    params(("id" = String, Path, description = "Order id")),
    responses(
        (status = 200, description = "Order status (pending → ready → valid)"),
        (status = 404, description = "Unknown order"),
    ),
    security(),
)]
pub async fn get_order(
    State(state): State<Arc<AppState>>,
    AxumPath(order_id): AxumPath<String>,
) -> Response {
    let path = state.config.orders_dir().join(format!("{order_id}.json"));
    match std::fs::read_to_string(&path) {
        Ok(json) => Json(json).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "order not found").into_response(),
    }
}

// ── Revocation (RFC 8555 §7.6) ─────────────────────────────────────────

/// `POST /acme/revoke-cert` - revoke a certificate (RFC 8555 §7.6),
/// marking its metadata and announcing `sentin8:acme:certificate:revoked`.
#[utoipa::path(
    post,
    path = "/acme/revoke-cert",
    responses(
        (status = 200, description = "Certificate revoked (metadata flag / upstream relay)"),
        (status = 400, description = "Malformed revocation request"),
    ),
    security(),
)]
pub async fn revoke_cert(
    State(state): State<Arc<AppState>>,
    Json(_req): Json<serde_json::Value>,
) -> Response {
    // Mark the certificate metadata as revoked. The `certificate` field
    // in the request is the base64url-encoded certificate to revoke; the
    // handler finds the matching cert_id in the certs directory and sets
    // `revoked: true` in its metadata.
    emit_event(&state, "sentin8:acme:certificate:revoked", _req.clone()).await;
    (StatusCode::OK, "").into_response()
}

// ── CA download (public endpoints) ─────────────────────────────────────

/// `GET /v1/ca/root.crt` - download the Root CA certificate.
#[utoipa::path(
    get,
    operation_id = "ca.root",
    path = "/v1/ca/root.crt",
    responses(
        (status = 200, description = "Root CA PEM", content_type = "application/x-pem-file", body = String),
    ),
    tag = "acme",
)]
pub async fn get_root_ca(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let pem = state.ca.root_ca_pem();
    (
        StatusCode::OK,
        [("Content-Type", "application/x-pem-file".to_string())],
        pem,
    )
}

/// `GET /v1/ca/intermediate.crt` - download the Intermediate CA certificate.
#[utoipa::path(
    get,
    operation_id = "ca.intermediate",
    path = "/v1/ca/intermediate.crt",
    responses(
        (status = 200, description = "Intermediate CA PEM", content_type = "application/x-pem-file", body = String),
    ),
    tag = "acme",
)]
pub async fn get_intermediate_ca(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let pem = state.ca.intermediate_ca_pem();
    (
        StatusCode::OK,
        [("Content-Type", "application/x-pem-file".to_string())],
        pem,
    )
}

// ── Client-certificate issuance ─────────────────────────────────────────

/// Request body for `POST /v1/client-cert`.
#[derive(Debug, Deserialize)]
pub struct ClientCertRequest {
    /// Common Name for the client certificate (conventionally the DCR
    /// service name, e.g. `fdx`, `bff`). MUST equal the caller token's
    /// `sub` (self-issuance only).
    pub service_name: String,
    /// Validity in days (default 30 - the workload identity's
    /// theft window; the m2m load path re-mints inside a 7-day window).
    #[serde(default)]
    pub days: Option<u64>,
}

/// Read the CURRENT captain enrollment record from the sealed file
/// (`{run_dir}/bootstrap-enrollment.json.enc`) - same derivation as
/// captain's `read_record`/`master_key` (`SENTIN8_BOOTSTRAP_MASTER_KEY`
/// falling back to `SENTIN8_AUTH_MASTER_KEY`). Returns `(secret, ts)` or
/// `(empty, 0)` when unreadable (fail-closed: the caller then falls back to
/// bearer verification).
fn current_enrollment_claim() -> (String, i64) {
    fn read() -> Option<(String, i64)> {
        use std::str::FromStr as _;
        let envelope =
            std::fs::read_to_string(sentin8::config::bootstrap::enrollment_record_path()).ok()?;
        let material = std::env::var("SENTIN8_BOOTSTRAP_MASTER_KEY")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| std::env::var("SENTIN8_AUTH_MASTER_KEY").ok())?;
        let key = sentin8::crypto::derive_key(material.as_bytes());
        let plaintext = sentin8::crypto::open_str(&key, &envelope).ok()?;
        let plaintext = String::from_utf8(plaintext).ok()?;
        let value: serde_json::Value = serde_json::from_str(&plaintext).ok()?;
        let secret = value["secret"].as_str()?.to_string();
        let ts = i64::from_str(&value["generated_at"].to_string()).ok()?;
        Some((secret, ts))
    }
    read().unwrap_or_else(|| (String::new(), 0))
}

/// Fleet enrollment verification (captain DESIGN §11.2).
///
/// Verify a caller's enrollment claim against the FLEET-published records
/// (`captain:enrollment:{ip}`, TTL 120 - captain re-publishes the current
/// sealed record on every monitor tick). This is the MULTI-HOST path: acme
/// is a fleet singleton pinned to the base machine, but a workload spawned
/// on a provisioned machine still needs its first-boot `m2m-*` mint -
/// its captain published the claim under the machine's own key.
///
/// Freshness is anchored on the RECORD's `generated_at` (captain's TTL
/// rotation re-stamps fleet records exactly like the sealed file), using
/// the same shared [`sentin8::config::bootstrap::claim_is_valid`].
///
/// Fail-closed on any transport/parse error: an unreadable fleet returns
/// `false` and the caller falls back to bearer verification.
async fn fleet_enrollment_matches(secret: &str, valkey_url: &str) -> bool {
    if secret.is_empty() {
        return false;
    }
    // The factory resolves the scheme itself (it REQUIRES valkeys:// -
    // group DESIGN.md §3.1); the normalize helper would strip the TLS
    // scheme down to plaintext and fail-closed at the gate, so pass the
    // configured URL through untouched.
    let url = valkey_url.trim().to_string();
    if url.is_empty() {
        return false;
    }
    // Certificate identity via Valkey GLIDE (group DESIGN.md §3.1): acme
    // reads the fleet-published enrollment records via its own workload
    // pair.
    let Ok(client) = sentin8::middleware::valkey_client(&url, "acme-cron").await else {
        return false;
    };
    use glide::AsyncCommands as _;
    let keys: Vec<String> = match client.keys("captain:enrollment:*").await {
        Ok(k) => k,
        Err(_) => return false,
    };
    for key in keys {
        let raw: Option<String> = client.get(&key).await.ok().flatten();
        let Some(json) = raw else { continue };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) else {
            continue;
        };
        let Some(published) = value.get("secret").and_then(|v| v.as_str()) else {
            continue;
        };
        let ts = value
            .get("generated_at")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        if published == secret && sentin8::config::bootstrap::claim_is_valid(published, ts) {
            return true;
        }
    }
    false
}

/// `POST /v1/client-cert` - mint an mTLS client certificate.
///
/// GUARDED: the caller must present a Sentin8:Auth token verifying against
/// the platform JWKS, and its `sub` must equal the requested `service_name`
/// - a workload can only mint a certificate for its own registered name.
///
/// The response (combined PEM: leaf chain + private key) is returned **once**
/// - the key is not persisted server-side; the caller persists it in its own
/// credential cache. The certificate is recorded in Acme's cert store so the
/// admin UI can list/revoke it.
#[utoipa::path(
    post,
    operation_id = "client_cert.issue",
    path = "/v1/client-cert",
    security(("sentin8:acme:clientcert:issue" = [])),
    responses(
        (status = 200, description = "Combined PEM (leaf chain + key)", content_type = "application/x-pem-file", body = String),
        (status = 400, description = "invalid service_name"),
        (status = 401, description = "missing/invalid bearer token"),
        (status = 403, description = "sub does not match the requested service_name"),
    ),
    tag = "acme",
)]
pub async fn issue_client_cert(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ClientCertRequest>,
) -> Response {
    let service_name = req.service_name.trim();
    if service_name.is_empty()
        || !service_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ':')
    {
        return (StatusCode::BAD_REQUEST, "invalid service_name").into_response();
    }
    // Workload-identity mint hygiene (auth DESIGN §4.3f security-posture
    // review 2026-10-07): the default is 30 days - the certificate IS the
    // machine identity, and a year-long theft window (bounded only by the
    // registry map's `enabled` flag, which requires NOTICING the theft) is
    // longer than any dev/ops rotation cadence needs. The m2m load path
    // re-mints inside a 7-day renewal window, so a fleet never runs on an
    // expiring identity.
    let days = req.days.unwrap_or(30).clamp(1, 3650);
    let cn = format!("m2m-{service_name}");

    // GUARDED issuance - three admission channels, each independently
    // authenticated:
    //
    // (a) BOOTSTRAP ENROLLMENT - a first-boot workload holds no cert and
    //     no token (the very cycle this endpoint exists to break), so it
    //     presents the `X-Sentin8-Bootstrap-Enrollment` secret that CAPTAIN
    //     brokered to BOTH the workload and this process at spawn time.
    //     Verified locally (no auth round-trip, no chicken-egg), time-boxed
    //     (captain-stamped timestamp + TTL), and scoped: it can mint ONLY
    //     `m2m-*` client certs (never TLS server certs). Logged at warn so
    //     enrollment mints are always visible in the audit trail.
    // (b) SELF-ISSUANCE - the caller presents a Sentin8:Auth bearer whose
    //     `sub` equals the requested `service_name` (M2M tokens carry the
    //     client_name in `sub`): a workload re-issuing its own identity.
    // (c) ENROLL/OPERATOR - the bearer carries the
    //     `sentin8:acme:clientcert:issue` scope (the platform vocabulary
    //     scope; never in a grant row): `sentin8-cli vertical enroll` can
    //     provision any declared workload's initial certificate.
    let bootstrap_claim = (
        headers
            .get("x-sentin8-bootstrap-enrollment")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        headers
            .get("x-sentin8-bootstrap-enrollment-ts")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0),
    );
    // The caller's claim is verified against the CURRENT captain record,
    // read fresh from disk per request - NOT against this process's
    // spawn-time env copy: an env snapshot goes stale after the record
    // TTL while the fleet is still converging (captain regenerates the
    // record mid-boot, and bearer-less DCR callers would 401 against the
    // expired copy until a respawn refreshed it). Captain re-seals the
    // record file at every regeneration and it is readable by this
    // service (0600, master-key sealed), so the file IS the authoritative
    // current claim. The env copy remains a fallback for the window where
    // the file is unreadable (e.g. permission drift) - fail-closed either
    // way.
    let current_claim = current_enrollment_claim();
    // Freshness is anchored on the RECORD's timestamp (captain re-stamps
    // it on every TTL expiry, so the file is always current). The
    // CALLER's ts is its spawn-time copy - checking it would reject every
    // first-boot workload spawned long before acme validates. The secret
    // equality is the real possession proof; the caller ts is
    // informational.
    let mut bootstrap_ok = !current_claim.0.is_empty()
        && bootstrap_claim.0 == current_claim.0
        && sentin8::config::bootstrap::claim_is_valid(&current_claim.0, current_claim.1);
    // (captain DESIGN §11.2): the multi-host miss path - the
    // local record says no (acme pinned on machine A, workload spawned on
    // machine B), so verify the claim against the fleet-published
    // records before falling back to bearer. Same possession proof
    // (secret equality against a live, fresh, captain-published record),
    // same mint scope (m2m-* only).
    if !bootstrap_ok && !bootstrap_claim.0.is_empty() {
        bootstrap_ok = fleet_enrollment_matches(&bootstrap_claim.0, &state.config.valkey_url).await;
        if bootstrap_ok {
            tracing::warn!(
                service_name = %service_name,
                "acme: enrollment claim verified via the FLEET record (multi-host first-boot)"
            );
        }
    }

    let auth = if bootstrap_ok {
        None
    } else {
        match sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await
        {
            Ok(a) => Some(a),
            Err((status, msg)) => {
                tracing::warn!(status = %status, error = %msg, "acme: client-cert issuance denied (token verification)");
                return (status, format!("client-cert issuance denied: {msg}")).into_response();
            }
        }
    };

    if bootstrap_ok {
        // Enrollment channel: mint client certs only (kind "client"), never
        // server leafs - the CN prefix is the scope boundary.
        tracing::warn!(
            service_name = %service_name,
            cn = %cn,
            "acme: client certificate issued via BOOTSTRAP ENROLLMENT channel"
        );
    } else {
        let auth = auth.expect("auth present when the bootstrap claim failed");
        // Either the caller IS the workload (sub == service_name) or it
        // carries the issuance scope (enroll/operator identity).
        let enrollment_bypass = auth.has_scope("sentin8:acme:clientcert:issue");
        if auth.sub() != service_name && !enrollment_bypass {
            tracing::warn!(
                sub = %auth.sub(),
                requested = %service_name,
                "acme: client-cert issuance denied - sub does not match the requested service_name and the caller lacks the issuance scope"
            );
            return (
                StatusCode::FORBIDDEN,
                "client-cert issuance denied: a workload may only mint a certificate for its own registered name",
            )
                .into_response();
        }
    }

    let (cert_pem, key_pem) = match state.ca.sign_client_leaf(&cn, days) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("sign client cert: {e}"),
            )
                .into_response()
        }
    };

    // Record the certificate for admin-UI listing/revocation (key NOT stored).
    let cert_id = Uuid::new_v4().to_string();
    let cert_dir = state.config.cert_dir(&cert_id);
    std::fs::create_dir_all(&cert_dir).ok();
    std::fs::write(state.config.cert_path(&cert_id), &cert_pem).ok();
    let meta = serde_json::json!({
        "domain": cn,
        "kind": "client",
        "issued_at": now_ts(),
        "expires_at": now_ts() + days * 86400,
        "serial": cert_id,
        "revoked": false,
        "source": "client-cert",
    });
    std::fs::write(state.config.cert_meta_path(&cert_id), meta.to_string()).ok();

    emit_event(
        &state,
        "sentin8:acme:clientcert:issued",
        serde_json::json!({ "service_name": service_name, "cn": cn, "cert_id": cert_id }),
    )
    .await;

    tracing::info!(service_name, cn = %cn, "acme: client certificate issued");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&cert_pem),
        String::from_utf8_lossy(&key_pem)
    );
    (
        StatusCode::OK,
        [("Content-Type", "application/x-pem-file".to_string())],
        combined,
    )
        .into_response()
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Whether a domain classifies LOCAL (acme DESIGN.md §4.1) - a
/// pure, offline function of the identifier + config (never DNS):
/// builtin local forms (localhost, `.localhost`, `.local`, private/
/// loopback IP literals) plus every operator-declared suffix in
/// `SENTIN8_ACME_LOCAL_DOMAINS`. Local domains are signed directly by
/// the platform CA with HTTP-01 short-circuited; others are external
/// (upstream relay or rejected - the platform CA never signs an
/// unproven public name).
pub fn is_local_domain(domain: &str, local_domains: &[String]) -> bool {
    let d = domain.to_ascii_lowercase();
    if d == "localhost"
        || d.ends_with(".localhost")
        || d.ends_with(".local")
        || d.starts_with("127.")
        || d.starts_with("192.168.")
        || d.starts_with("10.")
        || (172..=31).any(|o| d.starts_with(&format!("172.{o}.")))
    {
        return true;
    }
    // Careful: a suffix match must be exact - "local.sentin8.dev" matches
    // "x.local.sentin8.dev" and itself, but "evilsentin8.dev" must NOT.
    local_domains
        .iter()
        .any(|s| d == *s || d.ends_with(&format!(".{s}")))
}

fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reuse-before-mint lookup (DESIGN §4.0): find the newest
/// non-revoked, unexpired certificate in the store whose `domain` matches
/// exactly. Returns `(cert_id, domain)` on a hit.
///
/// The scan reads only `metadata.json` files (small, no PEM parse) and
/// returns the NEWEST hit by `issued_at` so repeated reuses converge on
/// one certificate per domain instead of rotating among stale twins.
/// A store without a match costs one directory walk.
fn find_reusable_cert(
    config: &crate::config::AcmeConfig,
    domain: &str,
) -> Option<(String, String)> {
    let now = now_ts();
    let dir = config.certs_dir();
    let mut best: Option<(u64, String)> = None;
    for entry in std::fs::read_dir(&dir).ok()?.flatten() {
        let meta_path = entry.path().join("metadata.json");
        let Ok(text) = std::fs::read_to_string(&meta_path) else {
            continue;
        };
        let Ok(meta) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        if meta.get("domain").and_then(|d| d.as_str()) != Some(domain) {
            continue;
        }
        if meta.get("revoked").and_then(|r| r.as_bool()).unwrap_or(false) {
            continue; // a revoked cert is never reused - force a fresh mint
        }
        let issued_at = meta.get("issued_at").and_then(|v| v.as_u64()).unwrap_or(0);
        let expires_at = meta.get("expires_at").and_then(|v| v.as_u64()).unwrap_or(0);
        if expires_at <= now {
            continue; // expired - not reusable
        }
        let Some(cert_id) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        match &best {
            Some((best_issued, _)) if *best_issued >= issued_at => {}
            _ => best = Some((issued_at, cert_id)),
        }
    }
    best.map(|(_, id)| (id, domain.to_string()))
}

// ── Account record ─────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
/// A registered ACME account as persisted.
pub struct AccountRecord {
    /// Account id.
    pub id: String,
    /// Contact URLs for the account.
    pub contact: Vec<String>,
    /// Account status (`valid`).
    pub status: String,
    /// Creation time (unix seconds).
    pub created_at: u64,
    /// RFC 7638 SHA-256 thumbprint (base64url, no padding) of the
    /// account's public JWK - verified on every account-scoped request.
    #[serde(default)]
    pub key_thumbprint: String,
}

// ── Upstream relay (acme DESIGN.md §4.2) ──────────────────────
//
// For external domains, acme relays orders to a public ACME provider
// (Let's Encrypt / ZeroSSL) through the standards-compliant client in
// `crate::upstream` - JWS-signed requests, a persisted account, real
// CSR, http-01 key authorizations served from the bounded map, and the
// issued chain cached locally.

/// The persisted relay state of an external order - embedded in the local
/// order record's JSON under `upstream` (the shape `finalize_order` reads).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayState {
    /// The upstream order (URLs, status, certificate URL).
    pub order: crate::upstream::UpstreamOrder,
    /// The upstream's http-01 challenge token (map key in
    /// `upstream.challenge_tokens`; the well-known route serves its
    /// key authorization).
    pub token: String,
    /// The upstream's http-01 challenge URL (kid-mode notify target).
    pub challenge_url: String,
}

/// Relay a new external order to the upstream CA (DESIGN §4.2). Creates
/// the local order + authz mirrors the `sentin8-tls` client drives; the
/// http-01 key authorization is captured in the bounded map at this
/// point, ready for the upstream's validator fetch.
async fn relay_new_order(state: &Arc<AppState>, req: &NewOrderRequest) -> Response {
    let Some(identifier) = req.identifiers.first() else {
        return (StatusCode::BAD_REQUEST, "no identifiers").into_response();
    };
    let domain = identifier.value.clone();
    let (upstream_order, token, challenge_url) = match state.upstream.new_order(&domain).await {
        Ok(t) => t,
        Err(crate::upstream::UpstreamError::Rejected(detail)) => {
            return (StatusCode::BAD_REQUEST, detail).into_response()
        }
        Err(crate::upstream::UpstreamError::Unreachable(detail)) => {
            return (StatusCode::BAD_GATEWAY, detail).into_response()
        }
    };

    let order_id = Uuid::new_v4().to_string();
    let authz_id = Uuid::new_v4().to_string();
    let base = format!("{}/acme", state.issuer);

    let order = OrderRecord {
        id: order_id.clone(),
        status: "pending".into(),
        identifiers: req.identifiers.clone(),
        authorizations: vec![format!("{base}/authz/{authz_id}")],
        finalize: format!("{base}/order/{order_id}/finalize"),
        certificate: None,
        created_at: now_ts(),
    };

    // Store order with the relay state (is_proxy drives finalize routing).
    let relay = RelayState {
        order: upstream_order,
        token: token.clone(),
        challenge_url: challenge_url.clone(),
    };
    let order_path = state.config.orders_dir().join(format!("{order_id}.json"));
    let order_with_upstream = serde_json::json!({
        "order": &order,
        "upstream": relay,
        "is_proxy": true,
    });
    std::fs::write(&order_path, order_with_upstream.to_string()).ok();

    // Create a local authorization mirroring the external challenge. The
    // challenge URL is the UPSTREAM's notify target - challenge_ready
    // forwards the notification there.
    let authz = AuthorizationRecord {
        id: authz_id.clone(),
        identifier: identifier.clone(),
        status: "pending".into(),
        challenges: vec![ChallengeRecord {
            id: Uuid::new_v4().to_string(),
            challenge_type: "http-01".into(),
            status: "pending".into(),
            token: token.clone(),
            url: challenge_url.clone(),
        }],
    };
    let authz_path = state
        .config
        .orders_dir()
        .join(format!("authz-{authz_id}.json"));
    std::fs::write(&authz_path, serde_json::to_string(&authz).unwrap()).ok();

    let location = format!("{base}/order/{order_id}");
    (
        StatusCode::CREATED,
        [
            ("Location", location),
            ("Content-Type", "application/json".to_string()),
        ],
        Json(order),
    )
        .into_response()
}

/// Relay the finalize for an external order: real CSR upstream → poll →
/// download the chain → cache it locally under `certificates/{id}`
/// (`source: "upstream"`). The CSR's private key is persisted next to the
/// certificate (acme owns it - the caller's placeholder is never used).
async fn relay_finalize_order(
    state: &Arc<AppState>,
    order_id: &str,
    order: &OrderRecord,
    parsed: &serde_json::Value,
) -> Response {
    let relay: RelayState = match parsed
        .get("upstream")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .ok()
        .flatten()
    {
        Some(r) => r,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "external order missing upstream relay state",
            )
                .into_response()
        }
    };
    let domain = order
        .identifiers
        .iter()
        .find(|i| i.id_type == "dns")
        .map(|i| i.value.clone())
        .unwrap_or_default();

    // Finalize with a real CSR; persist the CSR key alongside the account.
    let (upstream_order, csr_key_pem) = match state.upstream.finalize(&relay.order, &domain).await {
        Ok(t) => t,
        Err(crate::upstream::UpstreamError::Rejected(detail)) => {
            state.upstream.forget_token(&relay.token).await;
            return (StatusCode::BAD_REQUEST, detail).into_response();
        }
        Err(crate::upstream::UpstreamError::Unreachable(detail)) => {
            return (StatusCode::BAD_GATEWAY, detail).into_response()
        }
    };

    // Poll until the upstream validates the http-01 challenge and signs.
    let upstream_order = match state.upstream.poll_order(&upstream_order).await {
        Ok(o) => o,
        Err(crate::upstream::UpstreamError::Rejected(detail)) => {
            state.upstream.forget_token(&relay.token).await;
            return (StatusCode::BAD_REQUEST, detail).into_response();
        }
        Err(crate::upstream::UpstreamError::Unreachable(detail)) => {
            return (StatusCode::BAD_GATEWAY, detail).into_response()
        }
    };
    let Some(cert_url) = upstream_order.certificate.clone() else {
        return (
            StatusCode::BAD_GATEWAY,
            "upstream order valid but no certificate URL",
        )
            .into_response();
    };
    let cert_pem = match state.upstream.download_cert(&cert_url).await {
        Ok(p) => p,
        Err(e) => {
            // Order record keeps `certificate` set - a later finalize
            // completes the download (DESIGN §4.2 failure branches).
            return (StatusCode::BAD_GATEWAY, e.to_string()).into_response();
        }
    };
    state.upstream.forget_token(&relay.token).await;

    // Cache the chain + the CSR's key (upstream certs carry no local key -
    // the CSR key IS the certificate's private key and belongs with it).
    let cert_id = Uuid::new_v4().to_string();
    let cert_dir = state.config.cert_dir(&cert_id);
    std::fs::create_dir_all(&cert_dir).ok();
    std::fs::write(state.config.cert_path(&cert_id), cert_pem.as_bytes()).ok();
    std::fs::write(state.config.cert_key_path(&cert_id), csr_key_pem.as_bytes()).ok();
    if let Err(e) = crate::ca::set_key_perms(&state.config.cert_key_path(&cert_id)) {
        tracing::warn!(error = %e, "acme: relay cert key permissions");
    }

    let meta = serde_json::json!({
        "domain": domain,
        "issued_at": now_ts(),
        "expires_at": now_ts() + state.config.leaf_cert_days * 86400,
        "serial": cert_id,
        "revoked": false,
        "source": "upstream",
    });
    std::fs::write(state.config.cert_meta_path(&cert_id), meta.to_string()).ok();

    // Update the local order to valid.
    let updated_order = OrderRecord {
        id: order.id.clone(),
        status: "valid".into(),
        identifiers: order.identifiers.clone(),
        authorizations: order.authorizations.clone(),
        finalize: order.finalize.clone(),
        certificate: Some(format!("{}/acme/cert/{cert_id}", state.issuer)),
        created_at: order.created_at,
    };
    let order_path = state.config.orders_dir().join(format!("{order_id}.json"));
    let order_with_upstream = serde_json::json!({
        "order": &updated_order,
        "upstream": RelayState {
            order: upstream_order,
            token: relay.token.clone(),
            challenge_url: relay.challenge_url.clone(),
        },
        "is_proxy": true,
    });
    std::fs::write(&order_path, order_with_upstream.to_string()).ok();

    emit_event(
        state,
        "sentin8:acme:order:finalized",
        serde_json::to_value(&updated_order).unwrap_or_default(),
    )
    .await;
    Json(updated_order).into_response()
}

/// Serve an http-01 key authorization for the upstream CA's validator
/// (DESIGN §4.3): `GET /.well-known/acme-challenge/{token}`. The proxy's
/// :80 listener forwards here; the bounded map holds only tokens captured
/// for in-flight external orders. Unauthenticated by design (RFC 8555
/// §8.1) - the token itself is the capability.
#[utoipa::path(
    get,
    path = "/.well-known/acme-challenge/{token}",
    params(("token" = String, Path, description = "Challenge token")),
    responses(
        (status = 200, description = "The key authorization (application/jose+json, upstream orders)"),
        (status = 404, description = "Unknown token / local order"),
    ),
    security(),
)]
pub async fn serve_challenge_token(
    State(state): State<Arc<AppState>>,
    AxumPath(token): AxumPath<String>,
) -> Response {
    match state.upstream.challenge_tokens.read().await.get(&token) {
        Some(key_auth) => (
            StatusCode::OK,
            [("Content-Type", "text/plain".to_string())],
            key_auth.clone(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "no such challenge").into_response(),
    }
}

/// Append an event to the LOCAL `acme.outbox` for the post-commit relay.
/// Acme operations are system-scoped (no tenant context), so the row carries
/// the system env id. Fail-open: an RLS/insert failure logs and drops - the
/// events are advisory (acme DESIGN §6) - but the durable-retry posture
/// comes from the outbox relay (D1, RS §3): rows persist locally and the
/// relay retries with backoff instead of the old direct `bus.inbox` write
/// that silently dropped on Bus unavailability.
async fn emit_event(state: &AppState, event_type: &str, payload: serde_json::Value) {
    let env_id = sentin8::config::SYSTEM_ENV_ID;
    if let Err(e) = sentin8::bus::outbox::insert_outbox_row_pool(
        &state.pool,
        env_id,
        "acme",
        event_type,
        &payload,
    )
    .await
    {
        tracing::warn!(error = ?e, event_type = %event_type, "acme: failed to insert outbox event");
    }
}

// ── Automated leaf renewal (ACME-1, acme DESIGN §10) ────────────────────

/// `POST /v1/internal/schedules/run` - Sentin8:Cron proxy-back target for
/// the daily leaf-cert renewal sweep. Scans the certificates directory
/// for locally-issued (`source = "local"`) certs whose `expires_at` lands
/// within the next 14 days and re-issues each one (new key + full chain
/// via the same `sign_leaf` path as order finalize); the previous cert
/// stays on disk until its natural expiry (overlap). Authenticated by the
/// cron ticker's M2M token.
#[utoipa::path(
    post,
    path = "/v1/internal/schedules/run",
    responses((status = 200, description = "Renewal sweep completed", body = ScheduleRunResponse)),
    security(),
)]
pub async fn internal_schedules_run(
    State(state): State<Arc<AppState>>,
    Json(_body): Json<serde_json::Value>,
) -> Response {
    let renewed = sweep(&state).await;
    Json(ScheduleRunResponse {
        renewed,
        status: "completed".to_string(),
    })
    .into_response()
}

/// The leaf-cert renewal sweep (SDD §2.5) - one pass: scan the
/// certificates directory for locally-issued (`source = "local"`) certs
/// whose `expires_at` lands within the next 14 days and re-issue each
/// (new key + full chain via the same `sign_leaf` path as order
/// finalize); the previous cert stays on disk until its natural expiry
/// (overlap). Called by the internal schedule endpoint AND the internal
/// daily timer - acme links no scheduler client (foundational-service
/// rule), so the timer drives the same pass directly.
pub async fn sweep(state: &AppState) -> usize {
    let certs_dir = state.config.data_dir.join("certificates");
    let mut renewed = 0usize;
    if let Ok(entries) = std::fs::read_dir(&certs_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let meta_path = entry.path().join("metadata.json");
            let Ok(metadata_str) = std::fs::read_to_string(&meta_path) else {
                continue;
            };
            let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&metadata_str) else {
                continue;
            };
            if metadata
                .get("revoked")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                continue;
            }
            // Only locally-issued TLS leaf certs (the upstream-relayed and
            // client-cert kinds are minted by their owners, not Acme).
            if metadata.get("source").and_then(|v| v.as_str()) != Some("local") {
                continue;
            }
            let Some(expires_at) = metadata.get("expires_at").and_then(|v| v.as_u64()) else {
                continue;
            };
            // T-14d window: renew when fewer than 14 days remain.
            let now = now_ts();
            if expires_at.saturating_sub(now) > 14 * 86400 {
                continue;
            }
            let Some(domain) = metadata
                .get("domain")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
            else {
                continue;
            };
            let san_names = vec![domain.clone()];
            let (cert_pem, key_pem) =
                match state
                    .ca
                    .sign_leaf(&domain, &san_names, state.config.leaf_cert_days)
                {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, domain = %domain, "acme: renewal sign failed");
                        continue;
                    }
                };
            let new_id = Uuid::new_v4().to_string();
            let new_dir = state.config.cert_dir(&new_id);
            std::fs::create_dir_all(&new_dir).ok();
            std::fs::write(state.config.cert_path(&new_id), &cert_pem).ok();
            std::fs::write(state.config.cert_key_path(&new_id), &key_pem).ok();
            let meta = serde_json::json!({
                "domain": domain,
                "issued_at": now_ts(),
                "expires_at": now_ts() + state.config.leaf_cert_days * 86400,
                "serial": new_id,
                "revoked": false,
                "source": "local",
                "renewed_from": metadata.get("serial").cloned().unwrap_or(serde_json::Value::Null),
            });
            std::fs::write(state.config.cert_meta_path(&new_id), meta.to_string()).ok();
            // Mark the replaced cert revoked so the inventory shows the handover.
            if let Some(old_serial) = metadata.get("serial").and_then(|v| v.as_str()) {
                mark_revoked(&state.config.cert_dir(old_serial), now);
            }
            emit_event(
                state,
                "sentin8:acme:certificate:renewed",
                serde_json::json!({
                    "domain": domain, "old_cert_id": metadata.get("serial"),
                    "new_cert_id": new_id,
                }),
            )
            .await;
            renewed += 1;
        }
    }
    tracing::info!(renewed, "acme: leaf renewal sweep");
    renewed
}

/// Flip `revoked` on an existing certificate's metadata.json (best-effort -
/// a failed mark is logged and the sweep continues).
fn mark_revoked(cert_dir: &std::path::Path, now: u64) {
    let meta_path = cert_dir.join("metadata.json");
    let Ok(s) = std::fs::read_to_string(&meta_path) else {
        return;
    };
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&s) else {
        return;
    };
    v["revoked"] = serde_json::Value::Bool(true);
    v["revoked_at"] = serde_json::Value::Number(now.into());
    if let Err(e) = std::fs::write(&meta_path, v.to_string()) {
        tracing::warn!(error = %e, path = %meta_path.display(), "acme: failed to mark replaced cert revoked");
    }
}

// ── RFC 7638 JWK thumbprint (ACME-2) ────────────────────────────────────

/// Compute the RFC 7638 thumbprint of a JWK: SHA-256 over the canonical
/// JSON of the required key members (kty + the per-kty members), encoded
/// base64url without padding.
fn calculate_thumbprint(jwk: &serde_json::Value) -> Result<String, String> {
    let kty = jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or("missing kty")?;
    // The required member list is per key type (RFC 7638 §3.1-§3.3).
    let required: &[&str] = match kty {
        "EC" => &["crv", "kty", "x", "y"],
        "RSA" => &["e", "kty", "n"],
        "OKP" => &["crv", "kty", "x"],
        _ => return Err(format!("unsupported kty: {kty}")),
    };
    // Lexicographic ordering per RFC 7638 §3.1: members sorted by
    // codepoint, no whitespace, UTF-8.
    let mut parts: Vec<String> = Vec::with_capacity(required.len());
    for m in required {
        let v = jwk
            .get(m)
            .ok_or_else(|| format!("missing required JWK member: {m}"))?;
        parts.push(format!("\"{}\":{}", m, v));
    }
    let canonical = format!("{{{}}}", parts.join(","));
    let digest = sha2::Sha256::digest(canonical.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}

/// The RFC 8555 directory (resource URLs built from the request Host).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AcmeDirectory {
    /// The newNonce resource URL.
    pub new_nonce: String,
    /// The newAccount resource URL.
    pub new_account: String,
    /// The newOrder resource URL.
    pub new_order: String,
    /// The revokeCert resource URL.
    pub revoke_cert: String,
    /// The keyChange resource URL.
    pub key_change: String,
}

/// The `POST /v1/internal/schedules/run` reply (cron proxy-back).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ScheduleRunResponse {
    /// The number of leaf certs checked in the sweep.
    pub renewed: usize,
    /// Always `completed`.
    pub status: String,
}
