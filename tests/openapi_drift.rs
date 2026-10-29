// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Contributors to the sentin8-acme
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI drift guard (OAPEC design §3) - bin-crate variant.
//!
//! The routed handlers live in the binary crate; an integration test cannot
//! link them, so this pins the dumped spec shape instead: `docs/openapi.json`
//! must exist and stay at or above the documented floor. Adding a served
//! route without an annotation drops the operation count only when a
//! companion annotation is removed - the authoritative router introspection
//! guard (`sentin8::shell::drift_guard`) applies to lib-router services;
//! tracks the bin-crate harness .

#[test]
fn openapi_dump_exists_and_exceeds_floor() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/openapi.json"))
        .expect("docs/openapi.json - regenerate via --print-registration --section=openapi");
    let spec: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    let paths = spec
        .get("paths")
        .and_then(|p| p.as_object())
        .expect("paths object");
    let ops: usize = paths
        .values()
        .map(|v| {
            v.as_object()
                .map(|o| o.keys().filter(|k| !k.starts_with("parameters")).count())
                .unwrap_or(0)
        })
        .sum();
    assert!(
        ops >= 18,
        "spec floor: expected >= 18 ops, got {ops} - an annotation was removed or stale"
    );
}
