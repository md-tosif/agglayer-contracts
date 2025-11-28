#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  upgrade-etrog-to-sovereign.sh \
    --old-tag <git-tag> \
    [--lbt-path <path-to-lbt-json>]
EOF
}

# --- Long flag parsing ---
ACTUAL_DIR=$(pwd)
TAG=""
LBT_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --old-tag)       TAG="${2:-}"; shift 2 ;;
    --lbt-path)      LBT_PATH="${2:-}"; shift 2 ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "Unknown flag: $1"; usage; exit 1 ;;
  esac
done

# --- Validation tag ---
[[ -n "$TAG" ]] || { echo "Missing --tag"; usage; exit 1; }

# --- Prepare manifest ---
./upgrade/upgradeEtrogSovereign/prepare-manifest.sh \
  --tag $TAG \

# --- Copy manifest ---
mkdir -p ./.openzeppelin
cp ./upgrade/upgradeEtrogSovereign/manifest-from-$TAG/* ./.openzeppelin/
echo "✔ Copy manifest"

# If LBT path provided, set `pathJsonInitLBT` in the copied upgrade_parameters.json (overwrite if exists)
if [[ -n "$LBT_PATH" ]]; then
  UPGR_JSON="./upgrade/upgradeEtrogSovereign/upgrade_parameters.json"
  if [[ -f "$UPGR_JSON" ]]; then
    env LBT_PATH="$LBT_PATH" UPGR_JSON="$UPGR_JSON" node - <<'NODE'
const fs = require('fs');
const p = process.env.UPGR_JSON;
const lbt = process.env.LBT_PATH;
try {
  const raw = fs.readFileSync(p, 'utf8');
  const obj = JSON.parse(raw);
  const existed = Object.prototype.hasOwnProperty.call(obj, 'pathJsonInitLBT');
  obj.pathJsonInitLBT = lbt;
  fs.writeFileSync(p, JSON.stringify(obj, null, 2) + '\n');
  console.log('✔ ' + (existed ? 'Overwrote' : 'Added') + ' pathJsonInitLBT in', p);
} catch (err) {
  console.error('Error updating', p + ':', err.message);
  process.exit(1);
}
NODE
  else
    echo "Warning: $UPGR_JSON not found, skipping LBT injection"
  fi
fi

# --- Upgrade script ---
npx hardhat run ./upgrade/upgradeEtrogSovereign/upgradeEtrogToSovereign.ts --network custom
echo "✔ Upgrade done!"