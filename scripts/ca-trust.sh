#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
# SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
# SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
# SPDX-License-Identifier: Apache-2.0
#
# ca-trust.sh - publish (or remove) the Sentin8 platform CA in the system
# and NSS trust stores.
#
# Usage:
#   sudo scripts/ca-trust.sh install            # all three families (default)
#   sudo scripts/ca-trust.sh install classical  # one family
#   sudo scripts/ca-trust.sh uninstall          # remove every Sentin8 anchor
#        scripts/ca-trust.sh status             # show what is installed
#
# Design: sentin8-acme DESIGN.md section 4.0b.
#
# WHY A SCRIPT AND NOT THE SERVICE PATH
#
# The acme service's boot-time install (SENTIN8_ACME_INSTALL_TRUST_STORE)
# publishes the ACTIVE family's ROOT only, to the OS store, best-effort.
# That is not enough to verify the platform end to end, and it is
# ambiguous across transport postures: the classical and exclusive CAs are
# entirely different authorities with different subjects, and an
# unnamespaced anchor (sentin8-root-ca.crt) gives no way to tell which
# posture it belongs to. This script names every file after its family.
#
# WHY ONE FILE PER CERTIFICATE
#
# Debian's update-ca-certificates copies each file in the anchor directory
# into the bundle verbatim; it does NOT split a PEM holding several
# certificates. The published acme-ca/root-ca.crt is a TWO-certificate
# bundle (root + intermediate), so installing that bundle as one anchor
# would make the INTERMEDIATE the anchor and leave the root as an
# unverified appendage. Every certificate therefore gets its own file.
#
# WHY THE INTERMEDIATE TOO
#
# Platform leafs serve the full chain, so a verifier that consumes the
# handshake does not strictly need the intermediate locally. Several
# verifiers are unreliable here: Chromium's path builder and
# `openssl s_client -CAfile` / `curl --cacert` with a root-only anchor can
# fail to build leaf -> intermediate -> root. Installing it is free.

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────

ALL_MODES=(classical hybrid exclusive)

# Filenames written by this script carry the family name, so the three
# postures can coexist and a human can tell which is which.
prefix_name() { printf 'sentin8-%s-%s-ca.crt' "$1" "$2"; }   # mode, kind

# Anchors written by older/acme boot-time paths. They carry no family name,
# which is the ambiguity this script exists to remove: they are removed on
# every install and uninstall.
LEGACY_NAMES=(
  sentin8-root-ca.crt
  sentin8-intermediate-ca.crt
  sentin8-local-ca.crt
)
LEGACY_NSS_NICKS=(
  'Sentin8 Local CA'
  'Sentin8 Intermediate CA'
  'Sentin8 Root CA'
)

# ── Helpers ────────────────────────────────────────────────────────────

say() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
  # An explicit anchor-dir override means "operate on this directory", which
  # is the test/sysroot mode - root is required only for the real system path.
  if [ -n "${SENTIN8_CA_ANCHOR_DIR:-}" ]; then return 0; fi
  [ "$(id -u)" -eq 0 ] || die "run this under sudo (it writes the system trust store)"
}

# Print the distro's anchor directory, or fail with a clear message.
# SENTIN8_CA_ANCHOR_DIR overrides the detected path - used by tests and by
# container images that stage anchors into a sysroot.
anchor_dir() {
  if [ -n "${SENTIN8_CA_ANCHOR_DIR:-}" ]; then
    printf '%s' "$SENTIN8_CA_ANCHOR_DIR"
  elif [ -d /usr/local/share/ca-certificates ]; then
    printf '%s' /usr/local/share/ca-certificates
  elif [ -d /etc/pki/ca-trust/source/anchors ]; then
    printf '%s' /etc/pki/ca-trust/source/anchors
  else
    die "no known CA anchor directory (neither Debian nor Fedora layout)"
  fi
}

# Rebuild the system bundle so added/removed anchors take effect.
# SENTIN8_CA_SKIP_REFRESH=1 skips it (tests, or a sysroot that has no
# trust tooling of its own).
refresh_bundle() {
  if [ "${SENTIN8_CA_SKIP_REFRESH:-0}" = "1" ]; then
    say "  bundle refresh skipped (SENTIN8_CA_SKIP_REFRESH=1)"
    return 0
  fi
  if command -v update-ca-certificates >/dev/null 2>&1; then
    update-ca-certificates --fresh >/dev/null
  elif command -v update-ca-trust >/dev/null 2>&1; then
    update-ca-trust extract >/dev/null
  else
    die "neither update-ca-certificates nor update-ca-trust is installed"
  fi
  say "  bundle refreshed"
}

# The acme data dir root, before per-mode scoping (PQCA-1).
acme_base_dir() {
  if [ -n "${SENTIN8_ACME_DATA_DIR:-}" ]; then
    printf '%s' "$SENTIN8_ACME_DATA_DIR"
  elif [ -n "${SENTIN8_STATE_DIR:-}" ]; then
    printf '%s/tls' "$SENTIN8_STATE_DIR"
  elif [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
    # Under sudo the operator's env is not inherited by default; fall back
    # to the FHS default the packaged runtime uses.
    printf '%s' /var/lib/sentin8/tls
  else
    printf '%s' "${HOME}/.sentin8/acme"
  fi
}

# The invoking (non-root) user's home, for the NSS database.
operator_home() {
  if [ -n "${SUDO_USER:-}" ]; then
    getent passwd "$SUDO_USER" | cut -d: -f6
  else
    printf '%s' "$HOME"
  fi
}

nss_db() { printf 'sql:%s/.pki/nssdb' "$(operator_home)"; }

# Add one certificate to the operator's NSS database. Best-effort: NSS is
# consumed by Chromium only and `certutil` is often absent.
nss_add() {
  local nick="$1" file="$2"
  command -v certutil >/dev/null 2>&1 || return 0
  local db; db="$(nss_db)"
  mkdir -p "$(operator_home)/.pki/nssdb" 2>/dev/null || return 0
  certutil -d "$db" -D -n "$nick" >/dev/null 2>&1 || true
  certutil -d "$db" -A -t 'CT,c,c' -n "$nick" -i "$file" >/dev/null 2>&1 || true
}

# Remove one nickname from the operator's NSS database.
nss_del() {
  local nick="$1"
  command -v certutil >/dev/null 2>&1 || return 0
  certutil -d "$(nss_db)" -D -n "$nick" >/dev/null 2>&1 || true
}

capitalise() {
  local s="$1"
  printf '%s%s' "$(printf '%s' "${s:0:1}" | tr '[:lower:]' '[:upper:]')" "${s:1}"
}

# ── Commands ───────────────────────────────────────────────────────────

cmd_status() {
  local dir; dir="$(anchor_dir)"
  say "anchor directory: $dir"
  local found=0
  for f in "$dir"/sentin8-*.crt; do
    [ -e "$f" ] || continue
    found=1
    local subj iss kind
    subj="$(openssl x509 -in "$f" -noout -subject 2>/dev/null | sed 's/^subject=//')"
    iss="$(openssl x509 -in "$f" -noout -issuer 2>/dev/null | sed 's/^issuer=//')"
    if [ "$subj" = "$iss" ]; then kind='root'; else kind='intermediate'; fi
    printf '  %-42s %-12s %s\n' "$(basename "$f")" "$kind" "$subj"
  done
  [ "$found" -eq 1 ] || say '  (no Sentin8 anchors installed)'

  if command -v certutil >/dev/null 2>&1; then
    say "NSS database: $(nss_db)"
    certutil -d "$(nss_db)" -L 2>/dev/null | grep -i 'sentin8' \
      | sed 's/^/  /' || say '  (no Sentin8 entries)'
  else
    say 'NSS: certutil not installed, nothing to inspect'
  fi
}

cmd_uninstall() {
  require_root
  local dir; dir="$(anchor_dir)"
  say "removing Sentin8 anchors from $dir"

  local removed=0
  for f in "$dir"/sentin8-*.crt; do
    [ -e "$f" ] || continue
    rm -f "$f"
    say "  removed $(basename "$f")"
    removed=$((removed + 1))
  done
  # Legacy unnamespaced anchors can predate the family-named layout.
  for n in "${LEGACY_NAMES[@]}"; do
    if [ -e "$dir/$n" ]; then
      rm -f "$dir/$n"
      say "  removed legacy $n"
      removed=$((removed + 1))
    fi
  done
  [ "$removed" -gt 0 ] || say '  (nothing to remove)'

  refresh_bundle

  # NSS: every family nickname plus the legacy ones.
  local mode kind nick
  for mode in "${ALL_MODES[@]}"; do
    for kind in root intermediate; do
      nss_del "Sentin8 $(capitalise "$mode") $(capitalise "$kind") CA"
    done
  done
  for nick in "${LEGACY_NSS_NICKS[@]}"; do nss_del "$nick"; done
  say 'done: no Sentin8 CA is trusted by the system store anymore'
}

cmd_install() {
  require_root
  local dir; dir="$(anchor_dir)"
  local base; base="$(acme_base_dir)"

  local modes=()
  if [ "$#" -gt 0 ]; then modes=("$@"); else modes=("${ALL_MODES[@]}"); fi

  say "anchor directory: $dir"
  say "CA data base:     $base"
  say "families:         ${modes[*]}"

  # Drop the ambiguous unnamespaced anchors first, so a stale
  # sentin8-root-ca.crt can never be mistaken for another posture's root.
  for n in "${LEGACY_NAMES[@]}"; do
    if [ -e "$dir/$n" ]; then
      rm -f "$dir/$n"
      say "  removed legacy ambiguous anchor $n"
    fi
  done

  local installed=0 missing=()
  local mode kind src dest
  for mode in "${modes[@]}"; do
    for kind in root intermediate; do
      src="$base/$mode/ca/$kind-ca.crt"
      if [ ! -f "$src" ]; then
        missing+=("$mode/$kind")
        continue
      fi
      dest="$dir/$(prefix_name "$mode" "$kind")"
      install -m 0644 "$src" "$dest"
      say "  + $(basename "$dest")"
      installed=$((installed + 1))
      nss_add "Sentin8 $(capitalise "$mode") $(capitalise "$kind") CA" "$src"
    done
  done

  if [ "${#missing[@]}" -gt 0 ]; then
    say "  skipped (never minted - run 'make ca-tls' to create them): ${missing[*]}"
  fi

  [ "$installed" -gt 0 ] || die "no CA material found under $base; run 'make ca-tls' first"

  refresh_bundle
  say "done: $installed certificate(s) installed"
}

usage() {
  sed -n '/^# ca-trust.sh/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
}

# ── Entry point ────────────────────────────────────────────────────────

main() {
  local cmd="${1:-}"; shift || true
  case "$cmd" in
    install)   cmd_install "$@" ;;
    uninstall) cmd_uninstall ;;
    remove|delete) cmd_uninstall ;;
    status)    cmd_status ;;
    ''|-h|--help|help) usage ;;
    *) die "unknown command '$cmd' (install | uninstall | status)" ;;
  esac
}

main "$@"
