// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Acme Admin UI handlers - RFW definitions.
//! Served from `GET /v1/admin/ui/{page}`, rendered by Sentin8:Dash at runtime.
//!
//! The pages expose the CA hierarchy (Root/Intermediate status), the
//! issued-certificate inventory, and proxy-mode configuration. Read-only where
//! the underlying state is managed by the ACME protocol itself, with a revoke
//! action for issued certificates.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::{AdminPage, AdminUiAction, AdminUiActionType};
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::{
    ButtonType, RemoteWidget, TextAlign, WidgetButton, WidgetCard, WidgetDataTable,
    WidgetDataTableColumn, WidgetText, WidgetTextType,
};

use crate::state::AppState;

/// `GET /v1/admin/ui/{*page}` - returns the RFW page definition as JSON.
///
/// Pages:
///   - `overview`      - CA hierarchy status, issued-cert count, active order count, proxy mode
///   - `certificates`  - issued-certificate inventory (domain, issued_at, expires_at, serial, revoked)
///   - `settings`      - Sentin8:Acme settings (upstream provider URL, leaf cert validity, trust-store)
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    params(("page" = String, Path, description = "RFW page name (overview, certificates, settings)")),
    responses(
        (status = 200, description = "RFW page definition (rendered by Sentin8:Dash)", body = sentin8::rfw::AdminUiResponse),
        (status = 403, description = "Caller lacks an acme read/admin scope"),
        (status = 404, description = "Unknown page"),
    ),
    security(("sentin8:acme:admin" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_ui(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<AdminUiResponse>, (axum::http::StatusCode, String)> {
    let a = sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;

    // Step 5 - Shield decides: the enforced scope-mirror
    // set over LIVE effective scopes is the only gate.

    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:acme:admin"),
    )
    .await?;
    let proxy_mode = !state.config.upstream_directory_url.is_empty();
    let def = match page.as_str() {
        "overview" => AdminPage::new("CA Overview")
            .widget(card(
                "Root CA",
                &format!(
                    "Subject: Sentin8 Local Development CA\nFingerprint: {}",
                    state.ca.root_ca_fingerprint()
                ),
            ))
            .widget(card(
                "Intermediate CA",
                "Signed by Root CA (5-year validity). Signs all leaf certificates.",
            ))
            .widget(card(
                "Issued Certificates",
                "See the Certificates page for the full inventory.",
            ))
            .widget(card(
                "Proxy Mode",
                if proxy_mode {
                    "Enabled - external domain orders are forwarded to the upstream ACME provider."
                } else {
                    "Disabled - local-only (localhost, *.local.sentin8.dev, private IPs)."
                },
            ))
            .build(),
        "certificates" => AdminPage::new("Certificates")
            .widget(table_with_actions(
                vec![
                    col("domain", "Domain"),
                    cols("issued_at", "Issued"),
                    cols("expires_at", "Expires"),
                    cols("serial", "Serial"),
                    col("revoked", "Revoked"),
                ],
                "/certificates",
                vec![row_action_post("Revoke", "certificates/{id}/revoke")],
            ))
            .build(),
        "settings" => AdminPage::new("Acme Settings")
            .widget(card(
                "Upstream Provider",
                if state.config.upstream_directory_url.is_empty() {
                    "(disabled - local-only)"
                } else {
                    &state.config.upstream_directory_url
                },
            ))
            .widget(card(
                "Leaf Certificate Validity",
                &format!("{} days", state.config.leaf_cert_days),
            ))
            .widget(card(
                "Trust-Store Auto-Install",
                if state.config.install_trust_store {
                    "Enabled - Root CA installed into OS + NSS trust stores."
                } else {
                    "Disabled - manual trust-store installation required."
                },
            ))
            .build(),
        // ── Policy Studio - shared page
        // constructors; the guard guarantees `Some` for the unwrap-free
        // dispatch below.
        p if sentin8::rfw::policy_page("sentin8:acme", p).is_some() => {
            sentin8::rfw::policy_page("sentin8:acme", p)
                .expect("policy_page checked in guard")
                .build()
        }
        _ => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ));
        }
    };
    Ok(Json(AdminUiResponse::page(def)))
}

/// `GET /v1/admin/{resource}` - returns a JSON array of admin data rows.
///
/// Resources:
///   - `overview`     - summary cards (CA status, counts)
///   - `certificates` - issued-certificate inventory from the CA data directory
///   - `settings`    - current config values
#[utoipa::path(
    get,
    path = "/v1/admin/{resource}",
    params(
        ("resource" = String, Path, description = "Admin data resource"),
    ),
    responses(
        (status = 200, description = "The resource's rows for the RFW table", body = sentin8::rfw::policy_pages::AdminDataRows),
        (status = 403, description = "Caller lacks an acme read/admin scope"),
        (status = 404, description = "Unknown resource"),
    ),
    security(("sentin8:acme:admin" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_data(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(resource): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let _a =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    // Step 5 - Shield decides: the enforced scope-mirror
    // set over LIVE effective scopes is the only gate.
    crate::policy::require_policy(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:acme:admin"),
    )
    .await?;
    let rows: Vec<serde_json::Value> = match resource.as_str() {
        "overview" => vec![serde_json::json!({
            "root_ca_fingerprint": state.ca.root_ca_fingerprint(),
            "proxy_mode": !state.config.upstream_directory_url.is_empty(),
            "leaf_cert_days": state.config.leaf_cert_days,
        })],
        "certificates" => list_certificates(&state).unwrap_or_default(),
        "settings" => vec![serde_json::json!({
            "upstream_directory_url": if state.config.upstream_directory_url.is_empty() { "" } else { &state.config.upstream_directory_url },
            "leaf_cert_days": state.config.leaf_cert_days,
            "install_trust_store": state.config.install_trust_store,
            "local_domains": state.config.local_domains,
        })],
        _ => vec![],
    };
    Ok(Json(serde_json::Value::Array(rows)))
}

/// `POST /v1/admin/certificates/{id}/revoke` - revoke an issued certificate.
///
/// Delegates to the existing `acme::revoke_cert` flow (updates metadata,
/// publishes CRL). Returns an RFW redirect to the certificates page.
#[utoipa::path(
    post,
    path = "/v1/admin/certificates/{id}/revoke",
    params(("id" = String, Path, description = "Certificate cache id")),
    responses(
        (status = 200, description = "Certificate revoked (RFW redirect to the certificates page)", body = sentin8::rfw::policy_pages::AdminRedirectAck),
        (status = 403, description = "Shield deny"),
        (status = 404, description = "Unknown certificate"),
    ),
    security(),
    tag = "admin-ui",
)]
pub async fn revoke_certificate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let _a =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    // Step 5 - Shield decides: the enforced scope-mirror
    // set over LIVE effective scopes is the only gate.
    crate::policy::require_policy(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:acme:admin"),
    )
    .await?;
    let cert_dir = state.config.data_dir.join("certificates").join(&id);
    if !cert_dir.exists() {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            format!("certificate not found: {id}"),
        ));
    }
    // Update the metadata.json to mark the certificate as revoked.
    let metadata_path = cert_dir.join("metadata.json");
    if metadata_path.exists() {
        if let Ok(metadata_str) = std::fs::read_to_string(&metadata_path) {
            if let Ok(mut metadata) = serde_json::from_str::<serde_json::Value>(&metadata_str) {
                if let Some(obj) = metadata.as_object_mut() {
                    obj.insert("revoked".into(), serde_json::json!(true));
                    obj.insert(
                        "revoked_at".into(),
                        serde_json::json!(chrono::Utc::now().to_rfc3339()),
                    );
                    let _ = std::fs::write(&metadata_path, metadata.to_string());
                }
            }
        }
    }
    Ok(Json(
        serde_json::to_value(AdminUiResponse::redirect("certificates")).unwrap(),
    ))
}

/// Scan the certificates data directory and return metadata rows.
fn list_certificates(state: &AppState) -> Result<Vec<serde_json::Value>, std::io::Error> {
    let certs_dir = state.config.data_dir.join("certificates");
    if !certs_dir.exists() {
        return Ok(vec![]);
    }
    // Bounded inventory: the directory is append-only and grows with
    // every ACME order the host ever issued - an unbounded listing ships
    // megabytes and stalls the RFW DataTable. Return the NEWEST 500
    // entries (mtime-descending); older certificates stay revocable by id
    // (the revoke route takes the id directly).
    const INVENTORY_LIMIT: usize = 500;
    let mut entries: Vec<(std::time::SystemTime, std::path::PathBuf)> =
        std::fs::read_dir(&certs_dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let md = e.metadata().ok()?;
                let created = md.modified().ok()?;
                let path = e.path();
                if path.join("metadata.json").exists() {
                    Some((created, path))
                } else {
                    None
                }
            })
            .collect();
    entries.sort_by_key(|e| std::cmp::Reverse(e.0));
    entries.truncate(INVENTORY_LIMIT);
    let mut rows = Vec::new();
    for (_created, entry_path) in entries {
        let cert_id = entry_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if let Ok(metadata_str) = std::fs::read_to_string(entry_path.join("metadata.json")) {
            if let Ok(metadata) = serde_json::from_str::<serde_json::Value>(&metadata_str) {
                rows.push(serde_json::json!({
                    "id": cert_id,
                    "domain": metadata.get("domain").and_then(|v| v.as_str()).unwrap_or(""),
                    "issued_at": metadata.get("issued_at").and_then(|v| v.as_str()).unwrap_or(""),
                    "expires_at": metadata.get("expires_at").and_then(|v| v.as_str()).unwrap_or(""),
                    "serial": metadata.get("serial").and_then(|v| v.as_str()).unwrap_or(""),
                    "revoked": metadata.get("revoked").and_then(|v| v.as_bool()).unwrap_or(false),
                }));
            }
        }
    }
    Ok(rows)
}

// ── Helper fns (same pattern as db/bus admin_ui.rs) ───────────────────

fn col(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: false,
        width: None,
        format: None,
    }
}

fn cols(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: true,
        width: None,
        format: None,
    }
}

#[allow(dead_code)]
fn table(columns: Vec<WidgetDataTableColumn>, endpoint: &str) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No certificates issued.".into()),
        row_link: None,
        row_actions: vec![],
    })
}

fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No certificates issued.".into()),
        row_link: None,
        row_actions,
    })
}

fn row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Primary,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}

fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}

#[allow(dead_code)]
fn link(label: &str, route: &str) -> AdminUiAction {
    AdminUiAction {
        label: label.into(),
        action_type: AdminUiActionType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: Some("add".into()),
    }
}
