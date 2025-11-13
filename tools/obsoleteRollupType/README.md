# Obsolete rollup type
Script to call `obsoleteRollupType` function in the `AgglayerManager.sol` smart contract.

## Install
```
npm i
```

## Setup
### obsoleteRollupType
The script supports two modes of operation:

#### Mode 1: Direct List (obsoleteRollupTypes)
Specify exactly which rollup types to obsolete.

#### Mode 2: Exclusion List (excludedRollupTypesID)
Specify which rollup types to keep active; all others will be obsoleted.

**Note**: You must use either `obsoleteRollupTypes` OR `excludedRollupTypesID`, not both.

#### Config file parameters:
  - `type`: Specify the type of transaction execution:
    - `EOA`: If executing from a wallet, the script will execute the obsolete rollup type operation on the specified network
    - `Multisig`: If executing from a multisig, the script will output the calldata of the transaction to execute
    - `Timelock`: If executing through a timelock, the script will output the execute and schedule data to send to the timelock contract
  - `agglayerManagerAddress`: `AgglayerManager.sol` SC address
  - `timelockDelay (optional)`: at least it should be the minimum delay of the timelock smart contract
  - `timelockSalt (optional)`: timelock salt
  - `maxFeePerGas`: set custom gas
  - `maxPriorityFeePerGas`: set custom gas
  - `multiplierGas`: set custom gas
  - **EITHER** `obsoleteRollupTypes` (Mode 1): array of rollup type IDs to obsolete
    - Each element is a `rollupTypeID` (number) that will be marked as obsolete
  - **OR** `excludedRollupTypesID` (Mode 2): array of rollup type IDs to **exclude** from being obsoleted
    - The script will automatically fetch all rollup types from the AgglayerManager
    - It will exclude rollup types that are already obsolete
    - It will exclude rollup types in the `excludedRollupTypesID` array
    - All remaining rollup types will be marked as obsolete
- A network should be selected when running the script
  - examples: `-- sepolia` or `--mainnet`
  - This uses variables set in `hardhat.config.ts`
  - Which uses some environment variables that should be set in `.env`
> All paths are from root repository

## Usage
> All commands are done from root repository.

### Call 'obsoleteRollupType'

#### Mode 1: Direct List
Use when you want to specify exactly which rollup types to obsolete:

- Copy configuration file:
```
cp ./tools/obsoleteRollupType/obsoleteRollupType.json.example ./tools/obsoleteRollupType/obsoleteRollupType.json
```
- Edit the `obsoleteRollupTypes` array with the IDs you want to obsolete
- Run tool:
```
npx hardhat run ./tools/obsoleteRollupType/obsoleteRollupType.ts --network <network>
```

#### Mode 2: Exclusion List
Use when you want to obsolete all rollup types except specific ones:

- Copy configuration file:
```
cp ./tools/obsoleteRollupType/obsoleteRollupType.json.example ./tools/obsoleteRollupType/obsoleteRollupType.json
```
- Add `excludedRollupTypesID` array with the IDs you want to keep active
- Remove `obsoleteRollupTypes` array
- Run tool:
```
npx hardhat run ./tools/obsoleteRollupType/obsoleteRollupType.ts --network <network>
```

The script will automatically:
1. Fetch all rollup types from the AgglayerManager
2. Exclude those that are already obsolete
3. Exclude those in the `excludedRollupTypesID` list
4. Mark all remaining rollup types as obsolete

### 'obsoleteRollupType' from an EOA

Running the tool, the obsoleteRollupType transaction(s) will be sent directly

### 'obsoleteRollupType' Multisig

- Output: Transaction(s) to obsolete the rollup type(s)

### Generate 'obsoleteRollupType' data to the Timelock SC
- Set your parameters
- Run tool:
```
npx hardhat run ./tools/obsoleteRollupType/obsoleteRollupType.ts --network <network>
```
- Output:
  - scheduleData
  - executeData
> send data to the timelock contract address:
> - use your favourite browser extension
> - send tx to timelock address with hex data as `scheduleData`
> - wait `timelockDelay` and then send `executeData` to timelock address

