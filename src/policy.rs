// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! Shield (Sentin8:Policy) integration for acme.
//!
//! Thin re-export of the shared bridge (`sentin8::shield::runtime`) -
//! the consolidated implementation every service uses. Nothing is
//! service-specific here beyond the colon service_type.
//!
use std::sync::Arc;

// The full bridge is re-exported so handlers and tests can use any
// piece of the shared surface without reaching into `sentin8::policy`
// directly. Not every name is referenced by this service today.
#[allow(unused_imports)]
pub use sentin8::shield::runtime::{
    boot_full, check_policy, engine_for, policy_bus_client, request_ctx, require_policy,
    spawn_hot_reload,
};
pub use sentin8::shield::PolicyEngine as Engine;

/// Test helper: build a bare engine for acme (empty until `load` runs;
/// refuses to start on invalid policy text).
pub fn engine() -> Arc<Engine> {
    engine_for("sentin8:acme")
}
