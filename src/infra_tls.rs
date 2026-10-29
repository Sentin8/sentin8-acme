// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Infrastructure TLS materialization (sentin8 group DESIGN.md §3.1, §3.2).
//!
//! The Valkey data plane authenticates by certificate - TLS listener with
//! `tls-auth-clients yes`, the client cert's CN mapping to the ACL user of
//! the same name. The SERVER half of that channel needs a leaf certificate
//! minted from the platform CA BEFORE Valkey starts, and the local control
//! path (captain's UDS/loopback operations and dev tooling) needs its own
//! client pair because the TLS listener has no plaintext fallback.
//!
//! The PostgreSQL plane (§3.2) runs the same model: a TLS server leaf for
//! PostgreSQL itself, a TLS-only `pg_hba.conf` (hostssl + `cert` auth - no
//! plaintext listener, no passwords), and an operator client pair
//! (`m2m-postgres-ops`) mapped to the DDL superuser role through the
//! identity map. The per-workload rows of that map are appended by
//! `vertical enroll` - registration-driven, zero core vertical knowledge.
//!
//! All are minted here, offline: `--ensure-infra-tls` loads the existing
//! CA hierarchy (`CaHierarchy::ensure` - no network, no database) and
//! writes the material into the shared secrets tree. Idempotent - a fresh
//! mint happens only when the material is missing or expiring, so `make
//! infra-up` can run it unconditionally.
//!
//! Boot order (target state, no phases):
//! `make infra-tls` (this mode) → `make infra-up` (Valkey + PostgreSQL
//! start TLS-only) → `make start` (fleet; services already hold m2m pairs
//! minted at enrollment).

use std::path::{Path, PathBuf};

use crate::ca::CaHierarchy;
use crate::config::AcmeConfig;

/// Minimal offline config for the mint: only the CA-material fields matter
/// (data_dir + day windows). The fleet-only fields (captain-assigned port,
/// DB/Valkey/auth URLs) are inert placeholders - this mode touches no
/// network and no database, so they are never read.
pub fn offline_config() -> AcmeConfig {
    let data_dir =
        std::env::var("SENTIN8_ACME_DATA_DIR").unwrap_or_else(|_| sentin8::config::tls_dir());
    AcmeConfig {
        port: 0,
        data_dir: PathBuf::from(data_dir),
        root_ca_days: 3650,
        intermediate_ca_days: 1825,
        leaf_cert_days: std::env::var("SENTIN8_ACME_LEAF_CERT_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(90),
        install_trust_store: false,
        sentin8_domain: std::env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "local.sentin8.dev".into()),
        upstream_directory_url: String::new(),
        upstream_contact: String::new(),
        upstream_ca_pem: String::new(),
        local_domains: Vec::new(),
        database_url: String::new(),
        sentin8_bus_url: String::new(),
        stream_family: String::new(),
        valkey_url: String::new(),
        sentin8_auth_url: String::new(),
        auth_client: sentin8::auth::client::Client::new(sentin8::auth::client::ClientOptions {
            base_url: String::new(),
            ..Default::default()
        }),
    }
}

/// Directory holding the infra TLS material (server leaf + control pair).
/// Lives under the secrets tree next to the m2m identity dir - the same
/// `.run/secrets` the operator already owns.
fn infra_tls_dir() -> PathBuf {
    let secrets =
        std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "../.run/secrets".to_string());
    Path::new(&secrets).join("infra-tls")
}

/// The certificate renewal window - re-mint when the leaf expires within
/// this many days. Same hygiene the m2m load path applies to workload
/// pairs: an infra leaf that dies silently bricks every TLS handshake,
/// so the mint step never lets one run to expiry.
const RENEWAL_WINDOW_DAYS: i64 = 14;

/// Mint (or confirm) the infra TLS material: the Valkey server leaf
/// (`valkey-server.crt`/`.key`, CN `infra-valkey`, SANs localhost +
/// loopback IPs so local `valkeys://localhost:6379` handshakes complete)
/// and the local control client pair (`valkey-control.crt`/`.key`,
/// CN `m2m-valkey-control` - matches the enroll-provisioned ACL user of
/// that name: read-only infra keys, no `m2m:*` writes).
///
/// # Errors
/// Returns the CA signing error verbatim when a fresh mint fails - a
/// partial material set is a defect, not a degraded mode.
pub fn ensure_infra_tls(
    config: &AcmeConfig,
    mint_workloads: &[String],
) -> Result<EnsureReport, String> {
    let dir = infra_tls_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    // Publish the PUBLIC CA chain next to the material - compose mounts it
    // read-only into the Valkey container (`tls-ca-cert-file`). Both sides
    // need it: the server verifies client certs against it, and workload
    // clients trust the server leaf with it. The chain (root + intermediate)
    // is required - Acme leaves are signed by the INTERMEDIATE, so a
    // root-only file cannot chain them. The copy lives under the secrets
    // tree so the container never sees the Acme data dir (which holds the
    // CA PRIVATE keys).
    let ca_dir = dir
        .parent()
        .map(|p| p.join("acme-ca"))
        .unwrap_or_else(|| dir.join("acme-ca"));
    std::fs::create_dir_all(&ca_dir).map_err(|e| format!("create {}: {e}", ca_dir.display()))?;
    let root_ca_src = config.root_ca_cert_path();
    let int_ca_src = config.intermediate_ca_cert_path();
    let mut chain = std::fs::read(&root_ca_src)
        .map_err(|e| format!("read root CA {}: {e}", root_ca_src.display()))?;
    let int_pem = std::fs::read(&int_ca_src)
        .map_err(|e| format!("read intermediate CA {}: {e}", int_ca_src.display()))?;
    chain.extend_from_slice(&int_pem);
    std::fs::write(ca_dir.join("root-ca.crt"), &chain)
        .map_err(|e| format!("publish CA chain: {e}"))?;
    let report = EnsureReport {
        server_cert: ensure_leaf(
            config,
            &dir,
            "valkey-server",
            "infra-valkey",
            &[
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ],
        )?,
        control_cert: ensure_client_leaf(config, &dir, "valkey-control", "m2m-valkey-control")?,
        admin_cert: ensure_client_leaf(config, &dir, "valkey-admin", "m2m-valkey-admin")?,
        writer_cert: ensure_client_leaf(
            config,
            &dir,
            "valkey-registry-writer",
            "m2m-valkey-registry-writer",
        )?,
        // PostgreSQL certificate identity (group DESIGN.md §3.2): the TLS
        // server leaf (same profile as infra-valkey - SANs cover the
        // `localhost` hosts the service DSNs use) and the DDL/operator
        // identity. The ops pair is the valkey-admin analogue: bootstrap,
        // enroll, and dev tooling present it; the ident map (written below
        // the mint in `pg_ident.conf`) resolves its CN to the `sentin8`
        // superuser role.
        postgres_server_cert: ensure_leaf(
            config,
            &dir,
            "postgres-server",
            "infra-postgres",
            &[
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ],
        )?,
        postgres_ops_cert: ensure_client_leaf(config, &dir, "postgres-ops", "m2m-postgres-ops")?,
        // The TLS-only HBA + the identity map seed. Enroll appends the
        // per-workload rows to pg_ident.conf at registration time
        // (registration-driven - zero core vertical knowledge, §4.14);
        // this seed file carries the fixed operator mapping plus the map
        // header. PostgreSQL re-reads both files per connection, so rows
        // added later need no server reload.
        pg_hba_conf: ensure_pg_hba_conf(&dir)?,
        pg_ident_conf: ensure_pg_ident_conf(&dir)?,
        captain_cert: {
            // The supervisor's PRIMARY identity - minted into the m2m
            // identity dir with the same naming the SDK's factory reads
            // (colons → underscores). Fresh-boot deadlocks otherwise:
            // captain needs the pair to reach Valkey, needs acme to mint
            // it, and needs itself up to spawn acme. Offline mint here is
            // the bootstrap-order break (group DESIGN.md §3.1).
            let id_dir = m2m_identity_dir();
            ensure_client_leaf(config, &id_dir, "sentin8_captain", "m2m-sentin8:captain")?
        },
        conformance_suite_cert: ensure_leaf(
            config,
            &dir,
            "conformance-suite-server",
            "conformance-suite",
            // The OIDF rig's nginx ingress hostnames (auth DESIGN §9a.2
            // 1b): the suite's compose publishes :8443 under this public
            // dev-zone name (resolves 127.0.0.1), and the loopback forms
            // cover direct local probes.
            &[
                "localhost.emobix.co.uk".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ],
        )?,
        minted_workloads: {
            // Optional operator-supplied pre-mint list - same rationale as
            // the captain identity above: a service whose FIRST Valkey
            // connection is a hard boot gate cannot wait for the runtime
            // mint loop to reach acme.
            let id_dir = m2m_identity_dir();
            let mut minted = Vec::new();
            for w in mint_workloads {
                let base = w.replace(['/', ':'], "_");
                let cn = format!("m2m-{w}");
                let (_, did) = ensure_client_leaf(config, &id_dir, &base, &cn)?;
                minted.push((w.clone(), did));
            }
            minted
        },
    };
    Ok(report)
}

/// Result of an `--ensure-infra-tls` run: what was minted vs. reused.
#[derive(Debug)]
pub struct EnsureReport {
    /// `(path, minted?)` for the Valkey server leaf.
    pub server_cert: (PathBuf, bool),
    /// `(path, minted?)` for the local control pair (read-only healthchecks).
    pub control_cert: (PathBuf, bool),
    /// `(path, minted?)` for the operator admin pair (enroll's ACL pass).
    pub admin_cert: (PathBuf, bool),
    /// `(path, minted?)` for the registry-writer pair - the ONLY identity
    /// with write rights on the `m2m:*` authorization record (the CLI's
    /// `publish_service`/`set_enabled` present it).
    pub writer_cert: (PathBuf, bool),
    /// `(path, minted?)` for the PostgreSQL TLS server leaf (CN
    /// `infra-postgres`; group DESIGN.md §3.2).
    pub postgres_server_cert: (PathBuf, bool),
    /// `(path, minted?)` for the PostgreSQL operator pair (CN
    /// `m2m-postgres-ops`, mapped to the `sentin8` DDL role).
    pub postgres_ops_cert: (PathBuf, bool),
    /// Path of the TLS-only `pg_hba.conf` seed (compose mounts it read-only).
    pub pg_hba_conf: PathBuf,
    /// Path of the `pg_ident.conf` seed (enroll appends workload rows).
    pub pg_ident_conf: PathBuf,
    /// `(path, minted?)` for the captain's PRIMARY Valkey identity -
    /// minted offline into the m2m identity dir to break the fresh-boot
    /// deadlock (captain cannot wait for acme: it spawns acme).
    pub captain_cert: (PathBuf, bool),
    /// `(path, minted?)` for the OIDF conformance suite's nginx ingress
    /// leaf (CN `conformance-suite`, SAN `localhost.emobix.co.uk`) - the
    /// suite image ships a self-signed cert no browser trusts, so the
    /// rig mounts this platform-CA leaf over it (auth DESIGN §9a.2 1b,
    /// front-channel browser tests cannot run against an
    /// untrusted ingress).
    pub conformance_suite_cert: (PathBuf, bool),
    /// `(workload, minted?)` for each operator-requested pre-mint - the
    /// boot-order break for hard-gated services.
    pub minted_workloads: Vec<(String, bool)>,
}

/// The m2m identity dir - the same resolution the SDK's factory uses
/// (`SENTIN8_M2M_CREDENTIALS_DIR`, else `{SENTIN8_SECRETS_DIR}/m2m-
/// credentials`); the mint writes the same filenames the factory reads.
fn m2m_identity_dir() -> PathBuf {
    std::env::var("SENTIN8_M2M_CREDENTIALS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let secrets =
                std::env::var("SENTIN8_SECRETS_DIR").unwrap_or_else(|_| "../.run/secrets".into());
            PathBuf::from(secrets).join("m2m-credentials")
        })
}

/// Mint a named leaf when missing/exiring; return its cert path + whether
/// a fresh mint happened. `sans` may be empty for client-only leaves
/// (rcgen falls back to the CN; client-auth verification uses the CN).
fn ensure_leaf(
    config: &AcmeConfig,
    dir: &Path,
    base: &str,
    cn: &str,
    sans: &[String],
) -> Result<(PathBuf, bool), String> {
    let cert_path = dir.join(format!("{base}.crt"));
    let key_path = dir.join(format!("{base}.key"));
    if leaf_is_valid(&cert_path) {
        return Ok((cert_path, false));
    }
    let ca = CaHierarchy::ensure(config)?;
    let (cert_pem, key_pem) = ca.sign_leaf(cn, sans, config.leaf_cert_days)?;
    std::fs::write(&cert_path, &cert_pem)
        .map_err(|e| format!("write {}: {e}", cert_path.display()))?;
    std::fs::write(&key_path, &key_pem)
        .map_err(|e| format!("write {}: {e}", key_path.display()))?;
    set_owner_only(&cert_path)?;
    set_owner_only(&key_path)?;
    Ok((cert_path, true))
}

/// Mint a named client-auth leaf when missing/expiring; return its cert
/// path + whether a fresh mint happened. The EKU is `ClientAuth`
/// (`sign_client_leaf` - the same profile every workload m2m pair uses):
/// Valkey's server-side client-cert verification enforces purpose, so a
/// ServerAuth leaf is rejected with `unsupported certificate` (alert 43).
/// PostgreSQL's client-cert verification (`cert` auth) accepts the same
/// ClientAuth profile - one leaf format serves both planes.
fn ensure_client_leaf(
    config: &AcmeConfig,
    dir: &Path,
    base: &str,
    cn: &str,
) -> Result<(PathBuf, bool), String> {
    let cert_path = dir.join(format!("{base}.crt"));
    let key_path = dir.join(format!("{base}.key"));
    if leaf_is_valid(&cert_path) {
        return Ok((cert_path, false));
    }
    let ca = CaHierarchy::ensure(config)?;
    let (cert_pem, key_pem) = ca.sign_client_leaf(cn, config.leaf_cert_days)?;
    // The identity dir may not exist on a fresh tree (`.run` is
    // gitignored and fully disposable - a wholesale delete must not
    // break re-materialization).
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    std::fs::write(&cert_path, &cert_pem)
        .map_err(|e| format!("write {}: {e}", cert_path.display()))?;
    std::fs::write(&key_path, &key_pem)
        .map_err(|e| format!("write {}: {e}", key_path.display()))?;
    set_owner_only(&cert_path)?;
    set_owner_only(&key_path)?;
    Ok((cert_path, true))
}

/// The TLS-only host-based-authentication file for the PostgreSQL plane
/// (group DESIGN.md §3.2). Hostssl `cert` rules ONLY - no `host` (plaintext)
/// line exists, and the `cert` method means the certificate decides the
/// connection: no password is ever checked. The container-local
/// unix-socket `trust` line keeps `pg_isready` (the compose healthcheck)
/// and in-container operator shells working - it is not reachable from
/// outside the container.
fn pg_hba_conf_contents() -> &'static str {
    "# PostgreSQL certificate identity (group DESIGN.md §3.2).\n\
     # hostssl + cert ONLY - the plane is TLS-only, the certificate is the\n\
     # credential, and there are no passwords. `pgm` maps the client cert\n\
     # CN to the connecting role (see pg_ident.conf - registration-driven,\n\
     # appended by `sentin8-cli vertical enroll`).\n\
     local   all all                       trust\n\
     hostssl all all 127.0.0.1/32  cert map=pgm clientcert=verify-full\n\
     hostssl all all ::1/128       cert map=pgm clientcert=verify-full\n\
     hostssl all all all           cert map=pgm clientcert=verify-full\n"
}

/// The identity-map seed: the header plus the FIXED operator mapping (the
/// `valkey-admin` analogue - the DDL/ops identity `db bootstrap`, enroll,
/// and dev tooling present). Per-workload rows (`m2m-{workload}` →
/// `{role}`) are appended by `sentin8-cli vertical enroll` and `db
/// bootstrap` - the seed never encodes a service identity, and NO regex
/// row exists: an unmapped CN fails the `cert` rule closed (the Valkey
/// `default`-user-off posture, mirrored).
fn pg_ident_conf_contents() -> &'static str {
    "PostgreSQL certificate identity map (group DESIGN.md §3.2).\n\
     One map (`pgm`): SYSTEM-USERNAME is the client cert's CN, PG-USERNAME\n\
     is the connecting role. Rows are written by `make infra-tls` (the fixed\n\
     operator mapping below) and `sentin8-cli vertical enroll` (every\n\
     service's declared roles - registration-driven, zero core vertical\n\
     knowledge). PostgreSQL re-reads this file per connection - rows apply\n\
     without a server restart. An unmapped CN authenticates as nothing.\n\
     # MAPNAME  SYSTEM-USERNAME      PG-USERNAME\n\
     pgm        m2m-postgres-ops     sentin8\n"
}

/// Write the `pg_hba.conf`/`pg_ident.conf` seeds when missing. Unlike the
/// leaves these are static text - an existing file is left untouched so
/// the enroll-appended ident rows survive re-runs (the operator rows are
/// idempotent text; re-minting a cert never rewrites them).
fn ensure_pg_hba_conf(dir: &Path) -> Result<PathBuf, String> {
    let path = dir.join("pg_hba.conf");
    if !path.exists() {
        std::fs::write(&path, pg_hba_conf_contents())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(path)
}

/// [`ensure_pg_hba_conf`] - but for `pg_ident.conf`. Never overwrites: the
/// enroll pass owns the appended rows after first mint.
fn ensure_pg_ident_conf(dir: &Path) -> Result<PathBuf, String> {
    let path = dir.join("pg_ident.conf");
    if !path.exists() {
        std::fs::write(&path, pg_ident_conf_contents())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(path)
}

/// Whether the leaf on disk is present and outside the renewal window.
/// Reuses the m2m crate's NotAfter walk discipline: a PEM whose validity
/// cannot be parsed counts as invalid (fail toward mint, never toward
/// serving an unverifiable identity).
fn leaf_is_valid(cert_path: &Path) -> bool {
    let Ok(pem) = std::fs::read_to_string(cert_path) else {
        return false;
    };
    match crate::ca::pem_not_after(&pem) {
        Some(not_after) => {
            let now = chrono::Utc::now();
            now < not_after && (not_after - now).num_days() > RENEWAL_WINDOW_DAYS
        }
        None => false,
    }
}

/// 0600 - the `.key` files are private keys; the `.crt` files pair with
/// them and gain nothing from wider reads.
fn set_owner_only(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
