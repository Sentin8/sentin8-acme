// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Acme — internal ACME certificate authority server.
//!
//! Implements an ACME (RFC 8555) certificate authority for the Sentin8 platform.
//! Issues TLS certificates for all Sentin8 domains, including localhost and
//! internal hostnames that public CAs cannot sign. Installs its Root CA into
//! the OS trust store and Chromium/NSS trust store so browsers and system
//! tools trust the certificates automatically.

#![deny(missing_docs)]

/// ACME protocol handlers (RFC 8555).
pub mod acme;
/// Admin UI (RFW) handlers.
pub mod admin_ui;
/// CA hierarchy generation and leaf signing.
pub mod ca;
/// Environment configuration.
pub mod config;
/// Infrastructure TLS materialization (offline `--ensure-infra-tls` mode).
pub mod infra_tls;
/// OpenAPI spec assembly.
pub mod openapi;
/// Shield (Sentin8:Policy) integration — shared bridge re-exports.
pub mod policy;
/// Upstream ACME relay — RFC 8555 client for external domains (DEVDOM-2).
pub mod upstream;
/// Service self-registration declarations.
pub mod registration;
/// Mint admission control — bounded queue + load shed (ACME-PREF).
pub mod shed;
/// Axum router and server entry points.
pub mod server;
/// Shared application state.
pub mod state;
/// OS and Chromium/NSS trust-store installation.
pub mod truststore;

/// Serve the ACME certificate authority.
pub use server::serve;
