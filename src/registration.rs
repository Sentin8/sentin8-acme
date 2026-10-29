// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Sentin8:Acme.
//!
//! Output via `--print-registration` flag. The CLI runs the binary with this
//! flag and consumes the JSON to register the service in the platform DB.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, PgRole, PolicySetDecl, Registration, RelationDecl,
    SqlMigration,
};
use utoipa::OpenApi;

// Acme's bootstrap-tier DB identity (VDC §VDC.3b): acme creates the token
// plane and cannot fetch an M2M token before it exists, so its role
// authenticates with SCRAM (platform.sql seeds/converges the password).
// The role holds no tables; event emission rides the DBX producer path
// - a LOCAL `acme.outbox` drained to Bus's produce API (RS §3 D1: the
// direct `bus.inbox` INSERT grant is removed; no producer holds grants on
// Bus's internal durability tables).
const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "sentin8:acme:admin,sentin8:acme:read,sentin8:acme:clientcert:issue,
sentin8:tls:read",
    role: "sentin8_acme_service",
    bypass_rls: false,
    database: "sentin8",
    // Bus access rides the PRODUCE API over HTTPS (D1, RS §3) - acme's
    // local outbox is its only table; no cross-schema grants remain.
    cross_schema_grants: &[],
}];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "overview",
        label: "Overview",
        ui_endpoint: "/v1/admin/ui/overview",
        data_endpoint: "/v1/admin/overview",
        icon: "0xe1b1",
    },
    AdminUiPage {
        route: "certificates",
        label: "Certificates",
        ui_endpoint: "/v1/admin/ui/certificates",
        data_endpoint: "/v1/admin/certificates",
        icon: "0xe3c3",
    },
    AdminUiPage {
        route: "settings",
        label: "Settings",
        ui_endpoint: "/v1/admin/ui/settings",
        data_endpoint: "/v1/admin/settings",
        icon: "0xe57f",
    },
    AdminUiPage {
        route: "policy-sets",
        label: "Policy Sets",
        ui_endpoint: "/v1/admin/ui/policy-sets",
        data_endpoint: "/v1/admin/policy-sets",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "policy-decisions",
        label: "Policy Decisions",
        ui_endpoint: "/v1/admin/ui/policy-decisions",
        data_endpoint: "/v1/admin/policy-decisions",
        icon: "0xf070",
    },
];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

/// Serialize the utoipa OpenAPI spec (used for the `all` and `openapi` sections).
fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::AcmeOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

/// Default declarative policy sets: action-granular scope permits over the
/// LIVE effective scope set, seeded `origin='platform'`, `mode='enforced'`
/// (step 5 of the authorization pipeline is the only gate; shadow mode is
/// the emergency one-UPDATE rollback lever only).
const POLICIES: &[PolicySetDecl] = &[
    PolicySetDecl {
        policy_set_name: "scope-mirror",
        description: "Action-granular scope permits for sentin8:acme over the LIVE effective scope set. Enforced - step 5 is the only gate.",
        // Actions carry the acme service name (scope convention
        // {vertical}:{service}:{resource}:{action}). The registered admin
        // role is `sentin8:acme:admin`.
        policies: "permit(principal, action == Action::\"sentin8:acme:admin\", resource) when { principal.scopes.contains(\"sentin8:acme:admin\") };\npermit(principal, action == Action::\"sentin8:acme:read\", resource) when { principal.scopes.contains(\"sentin8:acme:read\") };",
        schema: None,
        mode: "enforced",
        default_enabled: true,
    },
];

/// Default ReBAC relation tuples - none declared by this
/// service today; env admins author their own graph via the admin API.
const RELATIONS: &[RelationDecl] = &[];

/// Print the registration JSON to stdout.
///
/// With no `--section` argument, outputs the full registration object.
/// With `--section=<name>`, outputs only that section as a standalone JSON value.
/// M2M DCR workload grants: this service's own workload rows, upserted by
/// `vertical enroll`. DCR is dynamic - this declaration is the ONLY
/// provisioning path (no static auth seed).
/// Cover BOTH the full-identity `-policy` spelling (policy_bus_client) and
/// the bare `{short}-policy` spelling (stat_emit); the gate's superset
/// check admits any requested subset.
const M2M_GRANTS: &[sentin8::registration::M2mGrant] = &[
    sentin8::registration::M2mGrant {
        workload: "acme-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:acme",
        scopes: &["sentin8:bus:produce", "sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:acme-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "acme-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    // Cron schedule self-registration (ACME-1): the boot registers the
    // recurring leaf-cert renewal sweep with Cron.
    sentin8::registration::M2mGrant {
        workload: "acme-cron",
        scopes: &["sentin8:cron:write"],
    },
    // (design/sentin8-vertical-data-plane-contract.md §VDC.7): the database-free HostContextResolver’s resolve workload - cache miss calls Sys `GET /v1/resolve/hostname`.
    sentin8::registration::M2mGrant {
        workload: "sentin8-acme-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

/// Print the registration JSON to stdout.
///
/// With no `--section` argument, outputs the full registration object.
/// With `--section=<name>`, outputs only that section as a standalone JSON value.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "sentin8:acme",
        subdomain: "acme",
        health_path: "/v1/health",
        admin_scopes: &[
            AdminScope::Tuple("sentin8:acme:admin", "sentin8:acme:admin"),
            // Policy-admin surface (per-service scope pair).
            AdminScope::Tuple("sentin8:acme:admin", "sentin8:acme:policy:read"),
            AdminScope::Tuple("sentin8:acme:admin", "sentin8:acme:policy:write"),
        ],
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "Acme",
            icon: "0xe06d",
            service_flag: "acme",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        pg_roles: PG_ROLES,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
