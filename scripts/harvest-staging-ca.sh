#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
# SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
# SPDX-FileCopyrightText: Copyright Contributors to the Sentin8
# SPDX-License-Identifier: Apache-2.0
#
# harvest-staging-ca.sh - extract the UPSTREAM CA that signed the fleet's
# external leaves, so the OIDF suite's JVM can verify them.
#
# Why this exists: the suite's Java client verifies SUT certificates strictly.
# `make conformance-up` imports the PLATFORM root into the JVM truststore,
# which covers every platform-CA host. When the fleet relays to Let's Encrypt
# staging, the tenant auth hosts carry a staging chain instead - and staging
# chains to a test root that is NOT in the OS store, so the JVM rejects them
# with `unable to find valid certification path`.
#
# The staging ROOTS change over time and are not shipped anywhere stable, so
# this script does not hardcode a PEM: it reads the chain acme actually
# STORED for a leaf it minted, and lifts the issuer certificate out of it.
# An intermediate is a valid JVM trust anchor, so importing it alone is
# sufficient (Java does not require the root when the anchor IS the issuer).
#
# Output: `staging-ca.crt` in the conformance build context, or a clear
# message when no upstream leaf exists yet (nothing has been minted).
#
# Usage:
#   sentin8-acme/scripts/harvest-staging-ca.sh [-o OUTFILE] [--print]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GROUP_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TREE_ROOT="$(cd "$GROUP_ROOT/.." && pwd)"

OUT="$GROUP_ROOT/sentin8-auth-oidf/conformance/staging-ca.crt"
PRINT=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output) OUT="$2"; shift 2 ;;
        --print) PRINT=1; shift ;;
        -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ -f "$TREE_ROOT/.env" ]]; then
    # Explicit caller env WINS over the file: an operator probing "what would
    # production harvest?" must not be silently answered for staging just
    # because the tree happens to be switched. Save, source, restore.
    _force="${SENTIN8_ACME_FORCE_INTERNAL-}"
    _dir="${SENTIN8_ACME_UPSTREAM_DIRECTORY_URL-}"
    _data="${SENTIN8_ACME_DATA_DIR-}"
    _mode="${SENTIN8_TLS_PQ_MODE-}"
    set -a
    # shellcheck disable=SC1090
    source "$TREE_ROOT/.env"
    set +a
    [[ -n "$_force" ]] && export SENTIN8_ACME_FORCE_INTERNAL="$_force"
    [[ -n "$_dir" ]] && export SENTIN8_ACME_UPSTREAM_DIRECTORY_URL="$_dir"
    [[ -n "$_data" ]] && export SENTIN8_ACME_DATA_DIR="$_data"
    [[ -n "$_mode" ]] && export SENTIN8_TLS_PQ_MODE="$_mode"
fi

ACME_BASE="${SENTIN8_ACME_DATA_DIR:-${SENTIN8_STATE_DIR:-/var/lib/sentin8}/tls}"
PQ_MODE="${SENTIN8_TLS_PQ_MODE:-exclusive}"
CERTS="$ACME_BASE/$PQ_MODE/certificates"

# CERTENV-1: scope the pick to the issuer environment the fleet is
# configured against RIGHT NOW. The store also holds leaves from other
# directories (a previous production run, a staging experiment), and
# harvesting the wrong one imports a CA that signed nothing in this run -
# the suite would then reject the actual SUT while trusting an unrelated
# anchor. The stamp is `upstream:{env}`; legacy records without it predate
# the field and were minted by production.
FORCE_INTERNAL="$(printf '%s' "${SENTIN8_ACME_FORCE_INTERNAL:-}" | tr '[:upper:]' '[:lower:]')"
DIRECTORY_URL="${SENTIN8_ACME_UPSTREAM_DIRECTORY_URL:-}"
if [[ "$FORCE_INTERNAL" == "true" || "$FORCE_INTERNAL" == "1" || -z "$DIRECTORY_URL" ]]; then
    ENV_WORD="local"
elif [[ "$DIRECTORY_URL" == *"acme-staging-v02.api.letsencrypt.org"* ]]; then
    ENV_WORD="staging"
elif [[ "$DIRECTORY_URL" == *"acme-v02.api.letsencrypt.org"* ]]; then
    ENV_WORD="production"
else
    # An unnamed provider: match the stamp prefix rather than guess a host.
    ENV_WORD=""
fi

if [[ -d "$CERTS" ]]; then
    echo "issuer env  : upstream:${ENV_WORD:-<any>}"
fi

if [[ ! -d "$CERTS" ]]; then
    echo "no certificate store at $CERTS - has the fleet minted anything?" >&2
    exit 1
fi

# Newest upstream-sourced leaf. `metadata.json` carries `source`; an
# upstream leaf's `cert.pem` is [leaf, issuer, (root)...] in issuance order,
# so the issuer is the SECOND block.
pick=$(python3 - "$CERTS" "$ENV_WORD" <<'PY'
import glob, json, os, sys
certs_dir, env_word = sys.argv[1], sys.argv[2]
best = None
for meta_path in glob.glob(os.path.join(certs_dir, "*", "metadata.json")):
    try:
        meta = json.load(open(meta_path))
    except Exception:
        continue
    if meta.get("source") != "upstream":
        continue
    # CERTENV-1 stamp; a legacy record (no `issuer`) predates the field and
    # was minted by production, so it must NOT satisfy a staging pick.
    stamp = meta.get("issuer") or "upstream:production"
    if env_word and stamp != f"upstream:{env_word}":
        continue
    cert = os.path.join(os.path.dirname(meta_path), "cert.pem")
    if not os.path.isfile(cert):
        continue
    key = (meta.get("issued_at") or 0, cert)
    if best is None or key > best:
        best = key
print(best[1] if best else "")
PY
)

if [[ -z "$pick" ]]; then
    if [[ -n "$ENV_WORD" ]]; then
        echo "no upstream:${ENV_WORD} leaf in $CERTS - nothing to harvest." >&2
        echo "The store holds leaves from another issuer environment (or none)," >&2
        echo "so importing one would trust a CA that signed nothing in this run." >&2
        echo "Mint against the configured directory first, then re-run." >&2
    else
        echo "no upstream-issued leaf in $CERTS - nothing to harvest yet." >&2
        echo "Mint one first (a handshake to an external host triggers the lazy" >&2
        echo "fetch), then re-run this script." >&2
    fi
    exit 3
fi

# The issuer block: everything after the first END CERTIFICATE.
issuer=$(python3 - "$pick" <<'PY'
import re, sys
pem = open(sys.argv[1], errors="replace").read()
blocks = re.findall(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S
)
if len(blocks) < 2:
    sys.exit(1)
print(blocks[1].strip())
PY
) || { echo "leaf $pick carries no issuer block" >&2; exit 1; }

subject=$(printf '%s\n' "$issuer" | openssl x509 -noout -subject -issuer 2>/dev/null | tr '\n' ' ')
echo "harvested from: $pick"
echo "  issuer cert : $subject"

if [[ "$PRINT" == "1" ]]; then
    printf '%s\n' "$issuer"
    exit 0
fi

printf '%s\n' "$issuer" > "$OUT"
chmod 644 "$OUT"
echo "wrote $OUT"
