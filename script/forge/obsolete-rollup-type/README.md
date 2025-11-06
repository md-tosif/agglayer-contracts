# Obsolete Rollup Type Script

This script generates calldata for obsoleting a rollup type in the AgglayerManager contract.

## Configuration

1. Copy the example configuration file:

   ```bash
   cp input.json.example input.json
   ```

2. Edit `input.json` with your network-specific settings:

   ```json
   {
       "1": {
           "agglayerManager": "0x5132A183E9F3CB7C848b0AAC5Ae0c4f0491B7aB2",
           "rollupTypeID": "1"
       },
       "11155111": {
           "agglayerManager": "0x5132A183E9F3CB7C848b0AAC5Ae0c4f0491B7aB2",
           "rollupTypeID": "2"
       }
   }
   ```

   - **Key**: Chain ID (e.g., `"1"` for Ethereum mainnet, `"11155111"` for Sepolia)
   - **agglayerManager**: Address of the AgglayerManager contract
   - **rollupTypeID**: ID of the rollup type to obsolete

## Usage

Run the script using Forge:

```bash
forge script script/forge/obsolete-rollup-type/ObsoleteRollupType.s.sol --rpc-url <RPC_URL>
```

### Example

```bash
forge script script/forge/obsolete-rollup-type/ObsoleteRollupType.s.sol --rpc-url $SEPOLIA_RPC_URL
```

## Output

The script will:

1. Validate that the rollup type is not already obsolete
2. Generate the calldata for the `obsoleteRollupType` function
3. Print the calldata to the console

The generated calldata can be used with a multisig wallet or governance system to execute the transaction.

## Requirements

- The rollup type must exist and not already be obsolete
- The AgglayerManager address must be valid (non-zero)
