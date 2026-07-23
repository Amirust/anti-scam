#!/usr/bin/env bash
set -euo pipefail

REPO="${ANTI_SCAM_REPO:-Amirust/anti-scam}"
BRANCH="${ANTI_SCAM_BRANCH:-master}"
CONFIG_URL="https://github.com/${REPO}/releases/latest/download/banned.json"
CHECKSUM_URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/banned.json.sha256"
OUT="${1:-banned.json}"

if [ -e "$OUT" ]; then
    printf '\033[1;31mwarning: %s already exists and will be OVERWRITTEN.\n' "$OUT"
    printf 'any entries added locally (e.g. via the "Add to dataset" button) will be lost.\033[0m\n'
    printf 'overwrite? [y/N] '
    read -r answer
    case "$answer" in
        [yY]|[yY][eE][sS]) ;;
        *)
            echo "aborted, keeping existing $OUT"
            exit 0
            ;;
    esac
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

echo "downloading config: ${CONFIG_URL}"
curl -fsSL "$CONFIG_URL" -o "$tmp"

echo "fetching expected checksum: ${CHECKSUM_URL}"
expected="$(curl -fsSL "$CHECKSUM_URL" | awk 'NF {print $1; exit}')"
if [ -z "$expected" ]; then
    echo "error: checksum file is empty" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp" | awk '{print $1}')"
else
    actual="$(shasum -a 256 "$tmp" | awk '{print $1}')"
fi

if [ "$expected" != "$actual" ]; then
    echo "CHECKSUM MISMATCH — not installing the config" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    echo "either the download is corrupted or the file was tampered with" >&2
    exit 1
fi

mv "$tmp" "$OUT"
trap - EXIT
echo "OK: $OUT (sha256 verified: $actual)"
