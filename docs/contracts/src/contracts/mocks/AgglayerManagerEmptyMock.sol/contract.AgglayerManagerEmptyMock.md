# AgglayerManagerEmptyMock
[Git Source](https://github.com/agglayer/agglayer-contracts/blob/97cad9ab107727514c9d0cc64270f595a4c37f2c/contracts/mocks/AgglayerManagerEmptyMock.sol)

**Inherits:**
[EmergencyManager](/contracts/lib/EmergencyManager.sol/contract.EmergencyManager.md)

AgglayerManager used only to test conensus contracts


## State Variables
### currentSequenceBatches

```solidity
uint256 currentSequenceBatches
```


### acceptSequenceBatches

```solidity
bool acceptSequenceBatches = true
```


## Functions
### setAcceptSequenceBatches


```solidity
function setAcceptSequenceBatches(bool newAcceptSequenceBatches) public;
```

### onSequenceBatches


```solidity
function onSequenceBatches(uint64 newSequencedBatches, bytes32 newAccInputHash) external returns (uint64);
```

### onVerifyBatches


```solidity
function onVerifyBatches(uint64 finalNewBatch, bytes32 newStateRoot, IPolygonRollupBase rollup)
    external
    returns (uint64);
```

### getBatchFee


```solidity
function getBatchFee() public view returns (uint256);
```

### getForcedBatchFee


```solidity
function getForcedBatchFee() public view returns (uint256);
```

### activateEmergencyState

Function to deactivate emergency state on both PolygonZkEVM and PolygonZkEVMBridge contracts


```solidity
function activateEmergencyState() external;
```

### lastDeactivatedEmergencyStateTimestamp

Function to deactivate emergency state on both PolygonZkEVM and PolygonZkEVMBridge contracts


```solidity
function lastDeactivatedEmergencyStateTimestamp() external returns (uint256);
```

### deactivateEmergencyState

Function to deactivate emergency state on both PolygonZkEVM and PolygonZkEVMBridge contracts


```solidity
function deactivateEmergencyState() external;
```

