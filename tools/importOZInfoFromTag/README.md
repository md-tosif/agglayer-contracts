# Import OpenZeppelin Info From Tag

Tool to generate OpenZeppelin manifest files from a specific git tag of the agglayer-contracts repository. This is needed for upgrades of contracts that were deployed in L2 genesis (where no OZ manifest exists).

## Purpose

When upgrading contracts like `PolygonZkEVMBridgeV2` and `PolygonZkEVMGlobalExitRootL2` that were deployed in the genesis of an L2 network, no OpenZeppelin network manifest file exists. This tool:

1. Clones the agglayer-contracts repo at a specific tag
2. Compiles the contracts from that version
3. Force imports the deployed contracts into OpenZeppelin's upgrade system
4. Generates the manifest files needed for safe upgrades

## Files

- `prepare-manifest.sh`: Main script that orchestrates the manifest generation
- `force-import-old-contracts.ts`: Hardhat script that force imports the bridge and GER contracts
- `upgrade_parameters.json`: Configuration with contract addresses to import

## Configuration

Update `upgrade_parameters.json` with the deployed contract addresses:

```json
{
    "bridgeL2": "0x...",
    "gerL2": "0x..."
}
```

## Usage

Run from the project root:

```bash
./tools/importOZInfoFromTag/prepare-manifest.sh --tag <git-tag> --url <rpc-url>
```

### Parameters

- `--tag`: Git tag of the agglayer-contracts repository (e.g., `v4.0.0-fork.7`)
- `--url`: L2 RPC URL for the target network

### Example

```bash
./tools/importOZInfoFromTag/prepare-manifest.sh --tag v4.0.0-fork.7 --url https://rpc.example.com
```

## Output

The script generates manifest files in:

```
upgrade/upgradeEtrogSovereign/manifest-from-<tag>/
```

These files should be copied to `.openzeppelin/` before running upgrade scripts.

## Related

This tool is used by the upgrade scripts in `upgrade/upgradeEtrogSovereign/`. See that folder's README for the full upgrade process.
