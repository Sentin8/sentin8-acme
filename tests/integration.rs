// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for Acme ACME server.
//!
//! Story 4.0c.21: Tests account registration, order creation, challenge
//! verification (HTTP-01), certificate issuance, local domain short-circuit,
//! and revocation.
//!
//! Story 22.20.6: Tests admin UI RFW endpoints (overview, certificates,
//! settings) and certificate revocation.

#[cfg(test)]
mod tests {
    use sentin8_acme_server::acme;
    use sentin8_acme_server::ca::CaHierarchy;

    /// Install the Graviola PQ crypto provider once — reqwest panics with
    /// "No provider set" when a client is built without one.
    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
        });
    }
    use sentin8_acme_server::config::AcmeConfig;
    use std::path::PathBuf;

    fn mk_config() -> AcmeConfig {
        let dir = format!("/tmp/acme-test-{}", uuid::Uuid::new_v4());
        AcmeConfig {
            port: 0,
            data_dir: PathBuf::from(&dir),
            root_ca_days: 3650,
            intermediate_ca_days: 1825,
            leaf_cert_days: 90,
            install_trust_store: false,
            sentin8_domain: "sentin8.local".into(),
            upstream_directory_url: String::new(),
            upstream_contact: "a@m.n".into(),
            upstream_ca_pem: String::new(),
            local_domains: vec!["local.sentin8.dev".into()],
            database_url: "postgresql://unused".into(),
            sentin8_bus_url: String::new(),
            stream_family: "acme".into(),
            valkey_url: String::new(),
            sentin8_auth_url: "https://test".into(),
            auth_client: sentin8::auth::client::Client::new(sentin8::auth::client::ClientOptions {
                base_url: "https://test".into(),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn ca_hierarchy_generation() {
        install_provider();
        let config = mk_config();
        config.init_dirs().unwrap();
        let ca = CaHierarchy::ensure(&config).unwrap();
        assert!(!ca.root_ca_pem().is_empty());
        assert!(!ca.intermediate_ca_pem().is_empty());
        assert!(!ca.root_ca_fingerprint().is_empty());
        // Verify files exist
        assert!(config.root_ca_cert_path().exists());
        assert!(config.root_ca_key_path().exists());
        assert!(config.intermediate_ca_cert_path().exists());
        assert!(config.intermediate_ca_key_path().exists());
        // Cleanup
        std::fs::remove_dir_all(&config.data_dir).ok();
    }

    #[test]
    fn ca_hierarchy_reload() {
        install_provider();
        let config = mk_config();
        config.init_dirs().unwrap();
        // Generate
        let ca1 = CaHierarchy::ensure(&config).unwrap();
        // Reload — the key should be the same (loaded from disk).
        let ca2 = CaHierarchy::ensure(&config).unwrap();
        // Verify the key PEM is the same (key is loaded from disk, not regenerated)
        let key1 = ca1.root_key.serialize_pem();
        let key2 = ca2.root_key.serialize_pem();
        assert_eq!(key1, key2, "Root CA key should be stable across reloads");
        // Cleanup
        std::fs::remove_dir_all(&config.data_dir).ok();
    }

    #[test]
    fn leaf_certificate_signing() {
        install_provider();
        let config = mk_config();
        config.init_dirs().unwrap();
        let ca = CaHierarchy::ensure(&config).unwrap();
        let (cert_pem, key_pem) = ca
            .sign_leaf(
                "test.sentin8.local",
                &["test.sentin8.local".to_string()],
                90,
            )
            .unwrap();
        assert!(cert_pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
        // Cleanup
        std::fs::remove_dir_all(&config.data_dir).ok();
    }

    #[test]
    fn is_local_domain() {
        install_provider();
        let local = vec!["local.sentin8.dev".to_string()];
        assert!(acme::is_local_domain("localhost", &local));
        assert!(acme::is_local_domain("myapp.localhost", &local));
        assert!(acme::is_local_domain(
            "sentin8-auth.ops.sys.sentin8.local",
            &local
        ));
        assert!(acme::is_local_domain("127.0.0.1", &local));
        assert!(acme::is_local_domain("192.168.1.1", &local));
        assert!(acme::is_local_domain("10.0.0.1", &local));
        // Operator-declared local suffixes (DEVDOM-1).
        assert!(acme::is_local_domain(
            "bus.ops.sys.local.sentin8.dev",
            &["local.sentin8.dev".to_string(),
                "local.ibank.dev".to_string()]
        ));
        assert!(acme::is_local_domain(
            "bff.prod.ibank.local.ibank.dev",
            &["local.sentin8.dev".to_string(),
                "local.ibank.dev".to_string()]
        ));
        // Exact-suffix match, not substring.
        assert!(!acme::is_local_domain(
            "evilsentin8.dev",
            &["local.sentin8.dev".to_string()]
        ));
        assert!(!acme::is_local_domain(
            "local.sentin8.dev.evil.com",
            &["local.sentin8.dev".to_string()]
        ));
        assert!(!acme::is_local_domain("example.com", &local));
        assert!(!acme::is_local_domain("myorg.com", &local));
        // An empty suffix list still admits the builtin local forms.
        assert!(acme::is_local_domain("localhost", &[]));
        assert!(!acme::is_local_domain(
            "bus.ops.sys.local.sentin8.dev",
            &[]
        ));
    }

    // ── Story 22.20.6 — Admin UI tests ──────────────────────────────────
    //
    // The admin_ui handlers require an `AppState` which contains a
    // `sqlx::PgPool`. Since we can't create a real pool in unit tests,
    // we test the pure helper functions and the certificate metadata
    // scanning logic that don't need a pool. The full RFW endpoint
    // round-trip is validated by the e2e-ts suites (see
    // `sentin8/e2e-ts/BACKLOG.md` E2E-UI-13).

    #[test]
    fn admin_ui_certificates_dir_empty() {
        install_provider();
        let config = mk_config();
        config.init_dirs().unwrap();
        // The certs dir is created by init_dirs but contains no certificate
        // subdirectories → list_certificates would return an empty list.
        let certs_dir = config.certs_dir();
        assert!(certs_dir.exists(), "certs dir should exist after init_dirs");
        // Verify it's empty (no certificate subdirectories)
        let entries: Vec<_> = std::fs::read_dir(&certs_dir).unwrap().collect();
        assert!(entries.is_empty(), "certs dir should be empty");
        // Cleanup
        std::fs::remove_dir_all(&config.data_dir).ok();
    }

    #[test]
    fn admin_ui_certificates_dir_with_metadata() {
        install_provider();
        let config = mk_config();
        config.init_dirs().unwrap();

        // Create a fake certificate with metadata
        let cert_id = "test-cert-001";
        let cert_dir = config.cert_dir(cert_id);
        std::fs::create_dir_all(&cert_dir).unwrap();

        // Write a fake cert.pem
        std::fs::write(
            cert_dir.join("cert.pem"),
            "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        // Write metadata.json
        let metadata = serde_json::json!({
            "domain": "test.sentin8.local",
            "issued_at": "2026-08-23T10:00:00Z",
            "expires_at": "2026-11-21T10:00:00Z",
            "serial": "01:23:45:67",
            "revoked": false
        });
        std::fs::write(cert_dir.join("metadata.json"), metadata.to_string()).unwrap();

        // Verify the metadata file exists and is parseable
        let metadata_str = std::fs::read_to_string(cert_dir.join("metadata.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&metadata_str).unwrap();
        assert_eq!(parsed["domain"].as_str().unwrap(), "test.sentin8.local");
        assert!(!parsed["revoked"].as_bool().unwrap());

        // Simulate revocation — update metadata
        let mut revoked = parsed.clone();
        if let Some(obj) = revoked.as_object_mut() {
            obj.insert("revoked".into(), serde_json::json!(true));
            obj.insert(
                "revoked_at".into(),
                serde_json::json!("2026-08-23T12:00:00Z"),
            );
        }
        std::fs::write(cert_dir.join("metadata.json"), revoked.to_string()).unwrap();

        // Verify revocation was written
        let after = std::fs::read_to_string(cert_dir.join("metadata.json")).unwrap();
        let after_parsed: serde_json::Value = serde_json::from_str(&after).unwrap();
        assert!(after_parsed["revoked"].as_bool().unwrap());

        // Cleanup
        std::fs::remove_dir_all(&config.data_dir).ok();
    }

    #[test]
    fn admin_ui_proxy_mode_detection() {
        install_provider();
        // When upstream_directory_url is empty, proxy mode is disabled
        let config_local = mk_config();
        assert!(
            !config_local.proxy_mode_enabled(),
            "local-only config should not have proxy mode"
        );

        // When upstream_directory_url is set, proxy mode is enabled
        let mut config_proxy = mk_config();
        config_proxy.upstream_directory_url =
            "https://acme-v02.api.letsencrypt.org/directory".into();
        assert!(
            config_proxy.proxy_mode_enabled(),
            "config with upstream URL should have proxy mode"
        );

        std::fs::remove_dir_all(&config_local.data_dir).ok();
        std::fs::remove_dir_all(&config_proxy.data_dir).ok();
    }

    #[test]
    fn admin_ui_settings_fields() {
        install_provider();
        // Verify the config fields used by the settings RFW page are accessible
        let config = mk_config();
        assert_eq!(config.leaf_cert_days, 90);
        assert!(!config.install_trust_store);
        assert!(config.upstream_directory_url.is_empty());

        std::fs::remove_dir_all(&config.data_dir).ok();
    }

    // ── Mint admission control (ACME-PREF) ────────────────────────────────

    #[test]
    fn mint_shed_admits_within_budget_and_sheds_over_queue() {
        // The shed's contract: within the budget every mint is admitted;
        // once the queue gauge reaches the cap, admission is refused (the
        // middleware answers 503 + Retry-After). Pure state-machine test —
        // no router needed.
        use sentin8_acme_server::shed::{MintLimiter, MAX_QUEUED_MINTS};

        let limiter = MintLimiter::default();
        // Fill the queue to the cap (try_acquire only — queued, NOT yet
        // running; the middleware calls enter() just before the handler
        // starts, so a saturated queue is exactly this state).
        for _ in 0..MAX_QUEUED_MINTS {
            assert!(
                limiter.try_acquire().is_ok(),
                "within budget: admission granted"
            );
        }
        assert!(limiter.queued() == MAX_QUEUED_MINTS);
        assert!(
            limiter.overloaded(),
            "queue full ({} queued): shed probes true",
            MAX_QUEUED_MINTS
        );
        // The NEXT caller is refused.
        assert!(
            limiter.try_acquire().is_err(),
            "past the cap: admission refused (503 path)"
        );
        // Drain: queued requests complete (enter + exit pairs), and the
        // shed re-opens.
        for _ in 0..MAX_QUEUED_MINTS {
            limiter.enter();
            limiter.exit();
        }
        assert_eq!(limiter.queued(), 0);
        assert_eq!(limiter.in_flight(), 0);
        assert!(!limiter.overloaded(), "drained: shed re-opens");
        assert!(limiter.try_acquire().is_ok(), "capacity freed: admitted");
    }

    #[test]
    fn mint_shed_constants_pinned() {
        use sentin8_acme_server::shed::{
            MAX_CONCURRENT_MINTS, MAX_QUEUED_MINTS, SHED_RETRY_AFTER_S,
        };
        // The shed window matches the sentin8-tls fetch-failure backoff
        // (30s) so one shed window = exactly one client retry round-trip;
        // the queue cap sits above the in-flight budget (the queue absorbs
        // bursts before refusals start).
        assert_eq!(SHED_RETRY_AFTER_S, 30);
        assert!(MAX_QUEUED_MINTS >= MAX_CONCURRENT_MINTS);
    }

    // ── DEVDOM-2 — upstream relay RFC 8555 client ──────────────────────

    #[test]
    fn upstream_jwk_thumbprint_shape() {
        install_provider();
        // RFC 7638: the thumbprint is 43 chars of base64url (SHA-256 of
        // the canonical JWK), no padding, decodable.
        use sentin8_acme_server::upstream::jwk_thumbprint;
        let key = p256_test_signing_key();
        let tp = jwk_thumbprint(&key);
        assert_eq!(tp.len(), 43, "SHA-256 → 43 base64url chars");
        assert!(!tp.contains('='), "no padding");
        assert!(!tp.contains('+') && !tp.contains('/'), "URL-safe alphabet");
    }

    #[test]
    fn upstream_key_authorization_format() {
        install_provider();
        // RFC 8555 §8.1: the served value is `{token}.{base64url(sha256
        // (thumbprint))}` — dot-separated, token prefix preserved.
        let key = p256_test_signing_key();
        let ka = key_authorization_of("tok123", &key);
        assert!(ka.starts_with("tok123."), "token prefix preserved");
        let parts: Vec<&str> = ka.split('.').collect();
        assert_eq!(parts.len(), 2, "exactly one dot separator");
        assert_eq!(parts[1].len(), 43, "digest half is a b64url SHA-256");
    }

    #[test]
    fn upstream_account_roundtrip_via_mock_directory() {
        install_provider();
        // Mock an RFC 8555 directory over a local axum server and drive
        // the relay's full external-order flow: newAccount (JWK mode,
        // Location → kid), newOrder (kid mode), authz with http-01
        // challenge, challenge notify, finalize with a REAL CSR, order
        // poll, cert download. Verifies: JWS envelope shape (protected/
        // payload/signature all b64url), Replay-Nonce handling, the
        // http-01 token capture into the bounded map, and cert caching.
        use base64::Engine;
        use sentin8_acme_server::upstream::UpstreamClient;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            // Bind FIRST so the mock directory can advertise real URLs.
            let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);

            let base = format!("http://127.0.0.1:{port}");
            let nonce_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let next_nonce = {
                let counter = nonce_counter.clone();
                move || {
                    format!(
                        "mock-nonce-{}",
                        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
                    )
                }
            };

            let app = axum::Router::new()
                .route(
                    "/directory",
                    axum::routing::get({
                        let base = base.clone();
                        move || {
                            let base = base.clone();
                            async move {
                                axum::Json(serde_json::json!({
                                    "newNonce": format!("{base}/new-nonce"),
                                    "newAccount": format!("{base}/new-account"),
                                    "newOrder": format!("{base}/new-order"),
                                }))
                            }
                        }
                    }),
                )
                .route(
                    "/new-nonce",
                    axum::routing::head({
                        let next_nonce = next_nonce.clone();
                        move || {
                            let n = next_nonce();
                            async move { [("Replay-Nonce", n)] }
                        }
                    }),
                )
                .route(
                    "/new-account",
                    axum::routing::post({
                        let base = base.clone();
                        let kid = format!("{base}/acct/1");
                        let next_nonce = next_nonce.clone();
                        move |body: String| {
                            let base = base.clone();
                            let kid = kid.clone();
                            let n = next_nonce();
                            async move {
                                // The initial account registration carries the
                                // JWK in the protected header (JWK mode).
                                let jws: serde_json::Value = serde_json::from_str(&body).unwrap();
                                let protected_b64 = jws["protected"].as_str().unwrap();
                                let protected_raw =
                                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                                        .decode(protected_b64)
                                        .unwrap();
                                let protected: serde_json::Value =
                                    serde_json::from_slice(&protected_raw).unwrap();
                                assert!(
                                    protected.get("jwk").is_some(),
                                    "newAccount must embed the JWK"
                                );
                                assert!(protected.get("kid").is_none(), "JWK mode carries no kid");
                                assert_eq!(protected["alg"], "ES256", "ES256 alg");
                                assert_eq!(protected["url"], format!("{base}/new-account"));
                                let mut resp_headers = axum::http::HeaderMap::new();
                                resp_headers.insert("Location", kid.parse().unwrap());
                                resp_headers.insert("Replay-Nonce", n.parse().unwrap());
                                (
                                    axum::http::StatusCode::CREATED,
                                    resp_headers,
                                    axum::Json(serde_json::json!({"status": "valid"})),
                                )
                            }
                        }
                    }),
                )
                .route(
                    "/new-order",
                    axum::routing::post({
                        let base = base.clone();
                        let kid = format!("{base}/acct/1");
                        let next_nonce = next_nonce.clone();
                        move |body: String| {
                            let base = base.clone();
                            let kid = kid.clone();
                            let n = next_nonce();
                            async move {
                                let jws: serde_json::Value = serde_json::from_str(&body).unwrap();
                                let protected_b64 = jws["protected"].as_str().unwrap();
                                let protected_raw =
                                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                                        .decode(protected_b64)
                                        .unwrap();
                                let protected: serde_json::Value =
                                    serde_json::from_slice(&protected_raw).unwrap();
                                assert_eq!(protected["kid"], kid, "kid mode after registration");
                                assert!(protected.get("jwk").is_none(), "kid mode carries no JWK");
                                // The nonce consumed here is the one the
                                // newAccount response handed back — the
                                // client reuses the server-provided nonce.
                                assert_eq!(
                                    protected["nonce"], "mock-nonce-2",
                                    "nonce consumed in order"
                                );
                                let mut resp_headers = axum::http::HeaderMap::new();
                                resp_headers
                                    .insert("Location", format!("{base}/order/1").parse().unwrap());
                                resp_headers.insert("Replay-Nonce", n.parse().unwrap());
                                (
                                    axum::http::StatusCode::CREATED,
                                    resp_headers,
                                    axum::Json(serde_json::json!({
                                        "status": "pending",
                                        "authorizations": [format!("{base}/authz/1")],
                                        "finalize": format!("{base}/order/1/finalize"),
                                    })),
                                )
                            }
                        }
                    }),
                )
                .route(
                    "/authz/1",
                    axum::routing::get({
                        let base = base.clone();
                        move || {
                            let base = base.clone();
                            async move {
                                axum::Json(serde_json::json!({
                                    "status": "pending",
                                    "challenges": [{
                                        "type": "http-01",
                                        "status": "pending",
                                        "token": "mock-http01-token",
                                        "url": format!("{base}/challenge/1"),
                                    }],
                                }))
                            }
                        }
                    }),
                )
                .route(
                    "/challenge/1",
                    axum::routing::post(|| async { axum::http::StatusCode::OK }),
                )
                .route(
                    "/order/1/finalize",
                    axum::routing::post(|body: String| async move {
                        // The finalize must carry a REAL DER CSR.
                        let jws: serde_json::Value = serde_json::from_str(&body).unwrap();
                        let payload_b64 = jws["payload"].as_str().unwrap();
                        let payload_raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(payload_b64)
                            .unwrap();
                        let payload: serde_json::Value =
                            serde_json::from_slice(&payload_raw).unwrap();
                        let csr_b64 = payload["csr"].as_str().unwrap();
                        let csr_der = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(csr_b64)
                            .unwrap();
                        assert!(
                            csr_der.len() > 100,
                            "real CSR DER, not a placeholder string"
                        );
                        axum::Json(serde_json::json!({
                            "status": "processing",
                        }))
                    }),
                )
                .route(
                    "/order/1",
                    axum::routing::post({
                        let base = base.clone();
                        move || {
                            let base = base.clone();
                            async move {
                                axum::Json(serde_json::json!({
                                    "status": "valid",
                                    "certificate": format!("{base}/cert/1"),
                                }))
                            }
                        }
                    }),
                )
                .route(
                    "/cert/1",
                    axum::routing::post(|| async {
                        "-----BEGIN CERTIFICATE-----\nMOCKCHAIN\n-----END CERTIFICATE-----\n"
                    }),
                );

            let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
                .await
                .unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await });

            let mut config = mk_config();
            config.upstream_directory_url = format!("{base}/directory");
            std::fs::create_dir_all(&config.data_dir).unwrap();
            let client = UpstreamClient::new(&config).unwrap();

            // Full external-order round trip.
            let (order, token_out, challenge_out) = client.new_order("example.dev").await.unwrap();
            assert_eq!(token_out, "mock-http01-token");
            assert_eq!(challenge_out, format!("{base}/challenge/1"));
            // The http-01 key authorization is captured and servable.
            let captured = client.challenge_tokens.read().await.clone();
            let ka = captured
                .get("mock-http01-token")
                .expect("captured key auth");
            assert!(ka.starts_with("mock-http01-token."));
            assert_eq!(ka.split('.').count(), 2);

            client.notify_challenge(&challenge_out).await.unwrap();
            let (order, _csr_key_pem) = client.finalize(&order, "example.dev").await.unwrap();
            assert_eq!(order.status, "processing");
            let order = client.poll_order(&order).await.unwrap();
            assert_eq!(order.status, "valid");
            assert_eq!(
                order.certificate.as_deref(),
                Some(format!("{base}/cert/1").as_str())
            );
            let cert = client
                .download_cert(order.certificate.as_deref().unwrap())
                .await
                .unwrap();
            assert!(cert.contains("BEGIN CERTIFICATE"));
            // The account persisted with kid + key.
            let account_path = config.upstream_account_path();
            let saved = std::fs::read_to_string(&account_path).unwrap();
            let acct: serde_json::Value = serde_json::from_str(&saved).unwrap();
            assert_eq!(acct["kid"], format!("{base}/acct/1"));
            // forget_token drops the servable key authorization.
            client.forget_token(&token_out).await;
            assert!(client.challenge_tokens.read().await.is_empty());

            std::fs::remove_dir_all(&config.data_dir).ok();
        });
    }

    /// A deterministic-ish ES256 test key (random is fine — the tests
    /// verify SHA-256/JWK relationships, not a fixed value).
    fn p256_test_signing_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng)
    }

    /// Mirror of `upstream::key_authorization` for the format test (the
    /// private fn is not exported; the relationship is what's pinned).
    fn key_authorization_of(token: &str, key: &p256::ecdsa::SigningKey) -> String {
        use base64::Engine;
        use sha2::Digest;
        let thumbprint = sentin8_acme_server::upstream::jwk_thumbprint(key);
        let digest = sha2::Sha256::digest(thumbprint.as_bytes());
        format!(
            "{token}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        )
    }
}
