#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
# SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
# SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Acme
# SPDX-License-Identifier: Apache-2.0
#
# migrate-certenv-1.sh - one-time layout move for CERTENV-1.
#
# CERTENV-1 namespaces every issuer-scoped store by the upstream issuer
# environment (local | staging | production | custom-{host}), so a directory
# switch can never serve a leaf, or present an account kid, that belongs to
# another directory. This script performs the ONE piece that cannot be done
# implicitly: moving the EXISTING leaves into their environment's directory.
#
# Why a script and not a boot path: the leaf cache is a flat file store with
# no provenance record (a PEM pair carries no "which CA signed me" field the
# SDK could trust), so the classification is a one-time operator decision.
# acme CAN migrate its own account file (it knows its directory URL and the
# kid's authority), and does so at boot - see UpstreamClient::adopt_legacy_account.
#
# Idempotent: run it as many times as you like; it only moves files that are
# still in the un-namespaced location and skips anything already in place.
#
# Usage:
#   sentin8-acme/scripts/migrate-certenv-1.sh              # dry run
#   sentin8-acme/scripts/migrate-certenv-1.sh --apply      # move files
#
# The classification is by ISSUER, read from each leaf's actual certificate:
#   - chain verifies against the platform root  -> local
#   - issuer CN is a Let's Encrypt intermediate -> production (the staging
#     run, if any, is identified with --staging-issuer)
# A leaf whose issuer cannot be classified is LEFT ALONE and reported: a
# wrong move is worse than a stale cache entry, which simply re-mints.
set -euo pipefail

APPLY=0
STAGING_HINT=""
for arg in "$@"; do
    case "$arg" in
        --apply) APPLY=1 ;;
        --staging-issuer=*) STAGING_HINT="${arg#*=}" ;;
        -h|--help)
            sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown argument: $arg (try --help)" >&2
            exit 2
            ;;
    esac
done

# Resolve the tree root from this script's location:
#   {tree}/sentin8/sentin8-acme/scripts/migrate-certenv-1.sh
# so the operator .env lives two levels up from the group folder.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GROUP_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TREE_ROOT="$(cd "$GROUP_ROOT/.." && pwd)"

if [[ -f "$TREE_ROOT/.env" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$TREE_ROOT/.env"
    set +a
fi

SECRETS_DIR="${SENTIN8_SECRETS_DIR:-$TREE_ROOT/.run/secrets}"
ACME_BASE="${SENTIN8_ACME_DATA_DIR:-${SENTIN8_STATE_DIR:-/var/lib/sentin8}/tls}"
PQ_MODE="${SENTIN8_TLS_PQ_MODE:-exclusive}"
case "$PQ_MODE" in
    classical|hybrid|exclusive) ;;
    *) echo "ERROR: unknown SENTIN8_TLS_PQ_MODE '$PQ_MODE'" >&2; exit 1 ;;
esac

CACHE_ROOT="$SECRETS_DIR/tls-certs/$PQ_MODE"
ROOT_CA="$ACME_BASE/$PQ_MODE/ca/root-ca.crt"

echo "CERTENV-1 leaf-cache migration"
echo "  pq mode      : $PQ_MODE"
echo "  cache root   : $CACHE_ROOT"
echo "  platform CA  : $ROOT_CA"
[[ "$APPLY" == "1" ]] && echo "  mode         : APPLY (files will move)" \
                    || echo "  mode         : DRY RUN (pass --apply to move)"

if [[ ! -d "$CACHE_ROOT" ]]; then
    echo "nothing to do - $CACHE_ROOT does not exist"
    exit 0
fi

# Already migrated? The env subdirectories are the only entries the new
# layout produces; a root holding them (and no *.crt) is done.
if ! compgen -G "$CACHE_ROOT/*.crt" >/dev/null; then
    echo "nothing to do - no un-namespaced leaves remain"
    exit 0
fi

# Classify one leaf: echo local|production|staging|unknown.
classify() {
    local crt="$1"
    # 1. Platform CA: the chain verifies against the platform root.
    if [[ -f "$ROOT_CA" ]] \
       && openssl verify -CAfile "$ROOT_CA" "$crt" >/dev/null 2>&1; then
        echo local
        return
    fi
    local issuer
    issuer="$(openssl x509 -in "$crt" -noout -issuer 2>/dev/null || true)"
    # 2. A Let's Encrypt intermediate. Staging and production chains share
    #    the ISRG roots, so an explicit issuer hint is the only reliable
    #    discriminator (the staging ECDSA intermediates are separate CNs).
    if [[ -n "$STAGING_HINT" && "$issuer" == *"$STAGING_HINT"* ]]; then
        echo staging
        return
    fi
    if [[ "$issuer" == *"Let's Encrypt"* ]]; then
        echo production
        return
    fi
    # 3. Anything else: a self-issued or third-party leaf. Do not guess.
    echo unknown
}

moved=0
skipped=0
unclassified=0
while IFS= read -r crt; do
    key="${crt%.crt}.key"
    host="$(basename "$crt" .crt)"
    env="$(classify "$crt")"
    if [[ "$env" == "unknown" ]]; then
        echo "  ? $host - issuer not classifiable, LEFT IN PLACE" >&2
        unclassified=$((unclassified + 1))
        continue
    fi
    dest="$CACHE_ROOT/$env"
    if [[ -f "$dest/$host.crt" ]]; then
        echo "  = $host - already present under $env/, leaving the old copy" >&2
        skipped=$((skipped + 1))
        continue
    fi
    echo "  → $host -> $env/"
    if [[ "$APPLY" == "1" ]]; then
        mkdir -p "$dest"
        chmod 700 "$dest"
        mv "$crt" "$dest/$host.crt"
        if [[ -f "$key" ]]; then
            mv "$key" "$dest/$host.key"
        fi
    fi
    moved=$((moved + 1))
done < <(find "$CACHE_ROOT" -maxdepth 1 -type f -name '*.crt' | sort)

echo
if [[ "$APPLY" == "1" ]]; then
    echo "moved $moved pair(s); $skipped already present; $unclassified unclassified"
else
    echo "would move $moved pair(s); $skipped already present; $unclassified unclassified"
    echo "(re-run with --apply to perform the move)"
fi
if [[ "$unclassified" -gt 0 ]]; then
    echo
    echo "NOTE: an unclassified leaf is not an error. The cache is load-or-mint:"
    echo "      a pair left in the root is simply never loaded, and the next"
    echo "      handshake for that hostname re-mints through the active issuer."
    echo "      Delete them once the fleet is healthy if you want the root clean."
fi
