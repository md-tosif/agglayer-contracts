#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  upgrade-etrog-to-sovereign.sh \
    --old-tag <git-tag> \
    --url <rpc-url> \
    [--lbt-path <path-to-lbt-json>]
EOF
}

# --- Long flag parsing ---
ACTUAL_DIR=$(pwd)
TAG=""
URL=""
LBT_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --old-tag)       TAG="${2:-}"; shift 2 ;;
    --url)           URL="${2:-}"; shift 2 ;;
    --lbt-path)      LBT_PATH="${2:-}"; shift 2 ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "Unknown flag: $1"; usage; exit 1 ;;
  esac
done

# --- Validation ---
[[ -n "$TAG" ]] || { echo "Missing --old-tag"; usage; exit 1; }
[[ -n "$URL" ]] || { echo "Missing --url"; usage; exit 1; }

# --- Prepare manifest ---
./tools/importOZInfoFromTag/prepare-manifest.sh \
  --tag $TAG \
  --url $URL

# --- Copy manifest ---
mkdir -p ./.openzeppelin
cp ./upgrade/upgradeEtrogSovereign/manifest-from-$TAG/* ./.openzeppelin/
echo "✔ Copy manifest"

# --- Upgrade script ---
npx hardhat run ./upgrade/upgradeEtrogSovereign/upgradeEtrogToSovereign.ts --network custom
echo "✔ Upgrade done!"