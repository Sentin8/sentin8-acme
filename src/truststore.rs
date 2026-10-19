// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
// SPDX-License-Identifier: Apache-2.0

//! OS and Chromium/NSS trust store installation.
//!
//! Stories 4.0c.13-4.0c.14: Install the Root CA into the OS trust store
//! and the Chromium/NSS database so browsers and system tools trust
//! Acme-issued certificates.

use std::path::Path;
use std::process::Command;

/// Install the Root CA into the OS trust store.
/// Returns Ok(()) on success, Err(message) on failure.
pub fn install_to_os_trust_store(ca_cert_path: &Path) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        install_linux(ca_cert_path)
    }
    #[cfg(target_os = "macos")]
    {
        install_macos(ca_cert_path)
    }
    #[cfg(target_os = "windows")]
    {
        install_windows(ca_cert_path)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = ca_cert_path;
        Err("unsupported OS for trust-store installation".into())
    }
}

#[cfg(target_os = "linux")]
fn install_linux(ca_cert_path: &Path) -> Result<(), String> {
    // Detect the distribution's trust store path.
    if Path::new("/usr/local/share/ca-certificates").exists() {
        // Debian/Ubuntu
        // The `certadmins` group (set up by infra/scripts/add-user-certadmins.sh)
        // gives write access to /usr/local/share/ca-certificates/ and allows
        // running `update-ca-certificates` via sudo (NOPASSWD sudoers drop-in).
        // No root privileges needed for the acme process itself.
        let dest = "/usr/local/share/ca-certificates/sentin8-local-ca.crt";
        std::fs::copy(ca_cert_path, dest).map_err(|e| {
            format!("copy CA cert: {e} - run infra/scripts/add-user-certadmins.sh first")
        })?;
        // Try without sudo first (works if already root), fall back to sudo
        // (works via the certadmins NOPASSWD sudoers drop-in).
        let output = Command::new("sudo")
            .args(["--non-interactive", "update-ca-certificates", "--fresh"])
            .output();
        match output {
            Ok(o) if o.status.success() => return Ok(()),
            Ok(o) => {
                // sudo failed - try without sudo (we might be root already)
                let output2 = Command::new("update-ca-certificates")
                    .arg("--fresh")
                    .output()
                    .map_err(|e| format!("run update-ca-certificates: {e}"))?;
                if output2.status.success() {
                    return Ok(());
                }
                return Err(format!(
                    "update-ca-certificates failed (sudo: {}, direct: {})",
                    String::from_utf8_lossy(&o.stderr),
                    String::from_utf8_lossy(&output2.stderr)
                ));
            }
            Err(e) => {
                // sudo not available - try direct
                let output2 = Command::new("update-ca-certificates")
                    .arg("--fresh")
                    .output()
                    .map_err(|e| format!("run update-ca-certificates: {e}"))?;
                if output2.status.success() {
                    return Ok(());
                }
                return Err(format!(
                    "update-ca-certificates failed: {} (sudo not available: {})",
                    String::from_utf8_lossy(&output2.stderr),
                    e
                ));
            }
        }
    }
    if Path::new("/etc/pki/ca-trust/source/anchors").exists() {
        // Fedora/RHEL
        let dest = "/etc/pki/ca-trust/source/anchors/sentin8-local-ca.crt";
        std::fs::copy(ca_cert_path, dest).map_err(|e| format!("copy CA cert: {e}"))?;
        let output = Command::new("sudo")
            .args(["--non-interactive", "update-ca-trust", "extract"])
            .output()
            .map_err(|e| format!("run update-ca-trust: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "update-ca-trust failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        return Ok(());
    }
    Err("could not detect Linux trust store path (neither Debian nor Fedora)".into())
}

#[cfg(target_os = "macos")]
fn install_macos(ca_cert_path: &Path) -> Result<(), String> {
    let output = Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
        ])
        .arg(ca_cert_path)
        .output()
        .map_err(|e| format!("run security: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "security failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_windows(ca_cert_path: &Path) -> Result<(), String> {
    let output = Command::new("certutil")
        .args(["-addstore", "-f", "Root"])
        .arg(ca_cert_path)
        .output()
        .map_err(|e| format!("run certutil: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "certutil failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

/// Install the Root CA into the Chromium/NSS trust store (~/.pki/nssdb).
/// This makes Chromium-based browsers trust the CA.
pub fn install_to_nss(ca_cert_path: &Path) -> Result<(), String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let nss_db = format!("{home}/.pki/nssdb");

    // Ensure the NSS db exists
    std::fs::create_dir_all(&nss_db).map_err(|e| format!("create nssdb: {e}"))?;

    // Remove existing entry (ignore errors)
    let _ = Command::new("certutil")
        .args([
            "-d",
            &format!("sql:{nss_db}"),
            "-D",
            "-n",
            "Sentin8 Local CA",
        ])
        .output();

    // Add the CA. Trust flags "CT,c,c":
    //   C  = valid CA (certificate issuer)
    //   T  = trusted CA for SSL (Chromium requires this to accept HTTPS certs)
    //   c  = trusted for S/MIME (email)
    //   c  = trusted for code signing
    // The previous "C,," only trusted the cert for email, NOT SSL, so
    // Chromium rejected the TLS cert with ERR_CERT_AUTHORITY_INVALID.
    let output = Command::new("certutil")
        .args([
            "-d",
            &format!("sql:{nss_db}"),
            "-A",
            "-t",
            "CT,c,c",
            "-n",
            "Sentin8 Local CA",
            "-i",
        ])
        .arg(ca_cert_path)
        .output();

    match output {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            tracing::warn!(
                "certutil (NSS) failed: {}. Chromium will not trust the CA until manually added.",
                String::from_utf8_lossy(&o.stderr)
            );
            Ok(()) // Non-fatal - NSS is only for Chromium
        }
        Err(_) => {
            tracing::warn!("certutil not found - skipping NSS trust store installation");
            Ok(())
        }
    }
}

/// Install the Intermediate CA into the Chromium/NSS trust store.
/// Chromium needs the intermediate in its trust store to build the full
/// chain (leaf → intermediate → root) - serving the intermediate in the
/// TLS handshake is not always sufficient for Chromium's cert verifier.
pub fn install_intermediate_to_nss(ca_cert_path: &Path) -> Result<(), String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let nss_db = format!("{home}/.pki/nssdb");

    std::fs::create_dir_all(&nss_db).map_err(|e| format!("create nssdb: {e}"))?;

    // Remove existing entry (ignore errors)
    let _ = Command::new("certutil")
        .args([
            "-d",
            &format!("sql:{nss_db}"),
            "-D",
            "-n",
            "Sentin8 Intermediate CA",
        ])
        .output();

    let output = Command::new("certutil")
        .args([
            "-d",
            &format!("sql:{nss_db}"),
            "-A",
            "-t",
            "CT,c,c",
            "-n",
            "Sentin8 Intermediate CA",
            "-i",
        ])
        .arg(ca_cert_path)
        .output();

    match output {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            tracing::warn!(
                "certutil (NSS intermediate) failed: {}.",
                String::from_utf8_lossy(&o.stderr)
            );
            Ok(())
        }
        Err(_) => {
            tracing::warn!("certutil not found - skipping NSS intermediate installation");
            Ok(())
        }
    }
}
