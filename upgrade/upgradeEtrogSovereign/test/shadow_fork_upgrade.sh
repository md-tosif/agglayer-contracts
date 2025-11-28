#!/bin/bash
export SCHEDULE_DATA=""
export EXECUTE_DATA=""
export ADMIN=""
export TIMELOCK_BALI=""
export RPC_SHADOW_FORK=""
export GER_L2=""
export BRIDGE_L2=""
export DELAY_TIMELOCK=""

# Try to load values from nearby JSON files if present
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PARAMS_FILE="$BASE_DIR/upgrade_parameters.json"
OUTPUT_FILE="$BASE_DIR/upgrade_output.json"

has_jq() {
	command -v jq >/dev/null 2>&1
}

if [ -f "$PARAMS_FILE" ]; then
	if has_jq; then
		RPC_SHADOW_FORK=$(jq -r '.forkParams.rpc // empty' "$PARAMS_FILE")
		ADMIN=$(jq -r '.forkParams.timelockAdminAddress // empty' "$PARAMS_FILE")
		BRIDGE_L2=$(jq -r '.bridgeL2 // empty' "$PARAMS_FILE")
		GER_L2=$(jq -r '.gerL2 // empty' "$PARAMS_FILE")
	else
		echo "Warning: 'jq' not found — cannot parse $PARAMS_FILE. Please install jq or set ADMIN and RPC_SHADOW_FORK manually."
	fi
else
	echo "Note: $PARAMS_FILE not found — will use environment variables if set."
fi

if [ -f "$OUTPUT_FILE" ]; then
	if has_jq; then
		SCHEDULE_DATA=$(jq -r '.scheduleData // empty' "$OUTPUT_FILE")
		EXECUTE_DATA=$(jq -r '.executeData // empty' "$OUTPUT_FILE")
		TIMELOCK_BALI=$(jq -r '.timelockContractAddress // empty' "$OUTPUT_FILE")
        DELAY_TIMELOCK=$(jq -r '.decodedScheduleData.delay // empty' "$OUTPUT_FILE")
    else
		echo "Warning: 'jq' not found — cannot parse $OUTPUT_FILE. Please install jq or set SCHEDULE_DATA, EXECUTE_DATA and TIMELOCK_BALI manually."
	fi
else
	echo "Note: $OUTPUT_FILE not found — will use environment variables if set."
fi

# Basic validation
missing=0
if [ -z "$RPC_SHADOW_FORK" ]; then
	echo "RPC (RPC_SHADOW_FORK) is empty. Set it in $PARAMS_FILE or export RPC_SHADOW_FORK."
	missing=1
fi
if [ -z "$ADMIN" ]; then
	echo "ADMIN (timelock admin) is empty. Set it in $PARAMS_FILE or export ADMIN."
	missing=1
fi
if [ -z "$BRIDGE_L2" ]; then
	echo "BRIDGE_L2 is empty. Set it in $PARAMS_FILE or export BRIDGE_L2."
	missing=1
fi
if [ -z "$GER_L2" ]; then
	echo "GER_L2 is empty. Set it in $PARAMS_FILE or export GER_L2."
	missing=1
fi
if [ -z "$SCHEDULE_DATA" ]; then
	echo "SCHEDULE_DATA is empty. Set it in $OUTPUT_FILE or export SCHEDULE_DATA."
	missing=1
fi
if [ -z "$EXECUTE_DATA" ]; then
	echo "EXECUTE_DATA is empty. Set it in $OUTPUT_FILE or export EXECUTE_DATA."
	missing=1
fi
if [ -z "$TIMELOCK_BALI" ]; then
	echo "TIMELOCK_BALI is empty. Set it in $OUTPUT_FILE or export TIMELOCK_BALI."
	missing=1
fi
if [ -z "$DELAY_TIMELOCK" ]; then
	echo "DELAY_TIMELOCK is empty. Set it in $OUTPUT_FILE or export DELAY_TIMELOCK."
	missing=1
fi
if [ $missing -eq 1 ]; then
	echo "One or more required variables are missing. Aborting."
	exit 1
fi

echo "Using RPC: $RPC_SHADOW_FORK"
echo "Using ADMIN: $ADMIN"
echo "Using TIMELOCK: $TIMELOCK_BALI"
echo "Using DELAY_TIMELOCK: $DELAY_TIMELOCK"

# Start the anvil node in the background
echo "Starting Anvil node..."
anvil --fork-url $RPC_SHADOW_FORK --block-time 12 > /dev/null 2>&1 &
ANVIL_PID=$!
echo "Anvil started with PID: $ANVIL_PID"

# Wait 5 seconds for Anvil to start up
echo "Waiting 5 seconds for Anvil to initialize..."
sleep 5

echo "Running upgrade operations..."

# Run the upgrade
echo "Impersonating account..."
cast rpc anvil_impersonateAccount $ADMIN

echo "Setting account balance..."
cast rpc anvil_setBalance $ADMIN 0x56BC75E2D63100000  # 100 ETH

echo "Scheduling batch operation..."
cast send $TIMELOCK_BALI $SCHEDULE_DATA --from $ADMIN --unlocked $ADMIN --legacy

echo "Moving forward delay timelock seconds..."
cast rpc anvil_increaseTime $DELAY_TIMELOCK --rpc-url http://localhost:8545

echo "Executing batch operation..."
cast send $TIMELOCK_BALI $EXECUTE_DATA --from $ADMIN --unlocked $ADMIN --legacy

echo "New BridgeL2 version"
cast call $BRIDGE_L2 "version()(string)" --rpc-url http://localhost:8545
echo "New GERL2 version"
cast call $GER_L2 "version()(string)"  --rpc-url http://localhost:8545

echo ""
echo "Upgrade complete!"
echo ""
echo "To kill the Anvil process, run: kill $ANVIL_PID"
