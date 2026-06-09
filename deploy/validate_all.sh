#!/usr/bin/env bash
# validate_all.sh — deploy a scenario and print its test commands
#
# Usage:
#   ./validate_all.sh <scenario_number> [suffix] [target_id]
#
# Examples:
#   ./validate_all.sh 01              # deploy scenario 01, auto-suffix from timestamp
#   ./validate_all.sh 04 abc123       # SCP scenario with custom suffix
#   ./validate_all.sh 12 abc123 ou-ab12-xxxxxxxx   # RCP+SCP attached to an OU
#
# After terraform apply, the script prints the validate_commands output so you
# can copy-paste the AWS CLI commands to verify each triple.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

SCENARIO="${1:-}"
if [[ -z "$SCENARIO" ]]; then
  echo "Usage: $0 <scenario_number> [suffix] [target_id]" >&2
  echo "Scenarios: 01 02 03 04 05 06 07 08 09 10 11 12" >&2
  exit 1
fi

SUFFIX="${2:-$(date +%s | tail -c 7)}"
TARGET_ID="${3:-}"

# Find the scenario directory by prefix number
SCENARIO_DIR=$(find "$SCRIPT_DIR" -maxdepth 1 -type d -name "${SCENARIO}_*" | head -1)
if [[ -z "$SCENARIO_DIR" ]]; then
  echo "Error: no scenario directory found matching prefix '${SCENARIO}'" >&2
  exit 1
fi

SCENARIO_NAME=$(basename "$SCENARIO_DIR")
echo "==> Deploying: $SCENARIO_NAME"
echo "    Suffix:    $SUFFIX"
[[ -n "$TARGET_ID" ]] && echo "    Target ID: $TARGET_ID"
echo ""

cd "$SCENARIO_DIR"
terraform init -upgrade -input=false

TF_VARS="-var=suffix=$SUFFIX"
[[ -n "$TARGET_ID" ]] && TF_VARS="$TF_VARS -var=target_id=$TARGET_ID"

terraform apply $TF_VARS -auto-approve

echo ""
echo "============================================================"
echo "  Validation commands for: $SCENARIO_NAME"
echo "============================================================"
terraform output -raw validate_commands 2>/dev/null || echo "(no validate_commands output defined)"
echo ""
echo "============================================================"
echo "Run 'terraform destroy $TF_VARS' to clean up when done."
