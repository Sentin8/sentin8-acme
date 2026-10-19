// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

use sentin8_acme_server::config::AcmeConfig;
use sentin8_acme_server::serve;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Check for --print-registration before any initialization.
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--print-registration") {
        let section = args
            .iter()
            .find_map(|a| a.strip_prefix("--section="))
            .map(|s| s.to_string());
        return sentin8_acme_server::registration::print(section);
    }

    // Offline infrastructure TLS materialization (sentin8 group DESIGN.md
    // §3.1, §3.2): mint the Valkey + PostgreSQL server leaves and the
    // local control/operator client pairs from the existing CA hierarchy
    // - no network, no database. Run by `make infra-tls` BEFORE `make
    // infra-up` (the TLS-only Valkey/PostgreSQL cannot boot without the
    // material). This mode builds a MINIMAL config - the fleet env vars
    // (captain-assigned port etc.) do not exist outside a captain-spawned
    // process.
    if args.iter().any(|a| a == "--ensure-infra-tls") {
        // The auth-client placeholder inside the minimal config builds a
        // reqwest client - the PQ provider must be installed first (this
        // mode runs before the shared install below).
        let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
        dotenvy::dotenv().ok();
        let config = sentin8_acme_server::infra_tls::offline_config();
        // Optional workload pre-mint: `--mint-workloads a,b,c` mints (or
        // confirms) each named workload's client pair into the m2m
        // identity dir - the boot-order break for services whose first
        // Valkey connection races acme's availability (group DESIGN.md
        // §3.1). The operator passes the platform catalog's service
        // identities; vertical services mint via their own shell path.
        let workloads: Vec<String> = args
            .iter()
            .find_map(|a| a.strip_prefix("--mint-workloads="))
            .map(|s| {
                s.split(',')
                    .map(|w| w.trim().to_string())
                    .filter(|w| !w.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        match sentin8_acme_server::infra_tls::ensure_infra_tls(&config, &workloads) {
            Ok(report) => {
                let (server, server_minted) = &report.server_cert;
                let (control, control_minted) = &report.control_cert;
                let (admin, admin_minted) = &report.admin_cert;
                let (writer, writer_minted) = &report.writer_cert;
                let (captain, captain_minted) = &report.captain_cert;
                println!(
                    "infra TLS: valkey server leaf {} ({})",
                    server.display(),
                    if *server_minted {
                        "minted"
                    } else {
                        "valid - reused"
                    }
                );
                println!(
                    "infra TLS: local control pair {} ({})",
                    control.display(),
                    if *control_minted {
                        "minted"
                    } else {
                        "valid - reused"
                    }
                );
                println!(
                    "infra TLS: operator admin pair {} ({})",
                    admin.display(),
                    if *admin_minted {
                        "minted"
                    } else {
                        "valid - reused"
                    }
                );
                println!(
                    "infra TLS: registry-writer pair {} ({})",
                    writer.display(),
                    if *writer_minted {
                        "minted"
                    } else {
                        "valid - reused"
                    }
                );
                let (pg_server, pg_server_minted) = &report.postgres_server_cert;
                let (pg_ops, pg_ops_minted) = &report.postgres_ops_cert;
                println!(
                    "infra TLS: postgres server leaf {} ({})",
                    pg_server.display(),
                    if *pg_server_minted {
                        "minted"
                    } else {
                        "valid - reused"
                    }
                );
                println!(
                    "infra TLS: postgres operator pair {} ({})",
                    pg_ops.display(),
                    if *pg_ops_minted {
                        "minted"
                    } else {
                        "valid - reused"
                    }
                );
                println!(
                    "infra TLS: pg_hba.conf seed {} / pg_ident.conf seed {}",
                    report.pg_hba_conf.display(),
                    report.pg_ident_conf.display()
                );
                println!(
                    "infra TLS: captain identity {} ({})",
                    captain.display(),
                    if *captain_minted {
                        "minted"
                    } else {
                        "valid - reused"
                    }
                );
                for (workload, minted) in &report.minted_workloads {
                    println!(
                        "infra TLS: workload '{workload}' pre-minted ({})",
                        if *minted {
                            "minted"
                        } else {
                            "valid - reused"
                        }
                    );
                }
                return Ok(());
            }
            Err(e) => {
                eprintln!("infra TLS materialization failed: {e}");
                return Err(anyhow::anyhow!("infra TLS materialization failed: {e}"));
            }
        }
    }

    // Install the Graviola PQ crypto provider before any reqwest HTTPS call.
    let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();

    dotenvy::dotenv().ok();
    let _ = sentin8::middleware::error_metrics::init_tracing_with_metrics(
        "sentin8:acme",
        std::env::var("RUST_LOG")
            .ok()
            .as_deref()
            .unwrap_or("sentin8_acme_server=info,tower_http=info,axum=info"),
    );
    sentin8::middleware::error_metrics::spawn_publisher(
        // VALKEYDERIVE-1: override → else the plane-derived URL.
        std::env::var("VALKEY_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(sentin8::config::service_valkey_url),
        "sentin8:acme",
    );

    let config = AcmeConfig::from_env();
    tracing::info!(
        service = "sentin8:acme",
        version = env!("CARGO_PKG_VERSION"),
        "service starting"
    );

    serve(config).await
}
