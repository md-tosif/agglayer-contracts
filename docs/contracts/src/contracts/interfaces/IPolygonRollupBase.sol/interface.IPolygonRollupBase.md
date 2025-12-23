# IPolygonRollupBase
[Git Source](https://github.com/agglayer/agglayer-contracts/blob/97cad9ab107727514c9d0cc64270f595a4c37f2c/contracts/interfaces/IPolygonRollupBase.sol)

**Inherits:**
[IPolygonConsensusBase](/contracts/interfaces/IPolygonConsensusBase.sol/interface.IPolygonConsensusBase.md)


## Functions
### onVerifyBatches


```solidity
function onVerifyBatches(uint64 lastVerifiedBatch, bytes32 newStateRoot, address aggregator) external;
```

### rollbackBatches


```solidity
function rollbackBatches(uint64 targetBatch, bytes32 accInputHashToRollback) external;
```

