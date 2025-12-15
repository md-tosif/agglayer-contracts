# Get LBT (Local Balance Tree)

Script to fetch and process `NewWrappedToken` events from a deployed bridge contract, and generate initialization data for LBT.

The script queries the blockchain for `NewWrappedToken` events emitted by the given contract.

For each wrapped token found, it retrieves its `totalSupply` and creates output files ready to be used for LBT initialization and bridge upgrades.

Additionally, the script handles:

- **Native token balance**: Calculates the unlocked native supply at the bridge contract
- **WETH token**: If the network has a gas token, includes WETH total supply

---

## Setup

### 1. Install packages

```bash
npm i
```

### 2. Set environment variables

```bash
cp .env.example .env
```

Fill `.env` with your `INFURA_PROJECT_ID` and `ETHERSCAN_API_KEY`

### 3. Copy configuration files

```bash
cp ./tools/getLBT/parameters.json.example ./tools/getLBT/parameters.json
```

### 4. Configure parameters

Update `parameters.json` with your settings:

```json
{
    "agglayerBridgeAddress": "0x...",
    "options": {
        "blockRange": 1000,
        "concurrencyLimit": 100,
        "printEvents": true,
        "printTokens": true,
        "getEventsFromFile": false,
        "outputPathTokensArray": "upgrade/upgradeEtrogSovereign/tokens.json",
        "outputPathLBT": "upgrade/upgradeEtrogSovereign/LBT.json",
        "blockNumber": "latest"
    }
}
```

#### Parameters Description

| Parameter                       | Required | Description                                                                                                          |
| ------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------- |
| `agglayerBridgeAddress`         | Yes      | Bridge contract address (AgglayerBridge)                                                                             |
| `options.blockRange`            | No       | Number of blocks per query batch. Default: `100000`                                                                  |
| `options.concurrencyLimit`      | No       | Maximum parallel RPC requests. Default: `10`. Increase for faster fetching, decrease if you encounter network errors |
| `options.printEvents`           | No       | If `true`, writes event data with totalSupply to `events.json`                                                       |
| `options.printTokens`           | No       | If `true`, writes token addresses array to a separate file (for bridge upgrade)                                      |
| `options.getEventsFromFile`     | No       | If `true`, reads events from `events.json` instead of fetching from chain                                            |
| `options.outputPathTokensArray` | No       | Custom output path for tokens file (relative to repo root). Example: `upgrade/upgradeEtrogSovereign/tokens.json`     |
| `options.outputPathLBT`         | No       | Custom output path for LBT file (relative to repo root). Example: `upgrade/upgradeEtrogSovereign/LBT.json`           |
| `options.blockNumber`           | No       | Block number for `totalSupply` query. Use `"latest"` or a specific block number                                      |

### 5. Run the script

```bash
npx hardhat run ./tools/getLBT/getLBT.ts --network <network>
```

---

## Output Files

### LBT File (`initializeLBT-{date}.json` or custom path)

Contains the complete LBT initialization data including all wrapped tokens, native token, and WETH:

```json
[
    {
        "wrappedTokenAddress": "0x...",
        "originNetwork": 0,
        "originTokenAddress": "0x...",
        "balance": "1000000000000000000"
    },
    {
        "wrappedTokenAddress": "0x0000000000000000000000000000000000000000",
        "originNetwork": 1,
        "originTokenAddress": "0x...",
        "balance": "500000000000000000"
    }
]
```

### Tokens File (`WTokens-{date}.json` or custom path)

Generated when `printTokens: true`. Contains token addresses for bridge upgrade:

```json
{
    "initNativeSupply": "200000000000000000000000000",
    "tokenAddresses": ["0xa2036f0538221a77A3937F1379699f44945018d0", "0x1E4a5963aBFD975d8c9021ce480b42188849D41d"]
}
```

### Events File (`events.json`)

Generated when `printEvents: true`. Contains raw event data with totalSupply for debugging or reuse:

```json
[
    {
        "blockNumber": "12345678",
        "originNetwork": "0",
        "originTokenAddress": "0x...",
        "wrappedTokenAddress": "0x...",
        "totalSupply": "1000000000000000000"
    }
]
```

---

## Related

This tool is typically used before running upgrade scripts in `upgrade/upgradeEtrogSovereign/`. See that folder's README for the full upgrade process.
