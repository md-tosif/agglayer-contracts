# IPolygonRollupBasePrevious
[Git Source](https://github.com/agglayer/agglayer-contracts/blob/97cad9ab107727514c9d0cc64270f595a4c37f2c/contracts/previousVersions/IPolygonRollupBasePrevious.sol)


## Functions
### initialize


```solidity
function initialize(
    address _admin,
    address sequencer,
    uint32 networkID,
    address gasTokenAddress,
    string memory sequencerURL,
    string memory _networkName
) external;
```

### onVerifyBatches


```solidity
function onVerifyBatches(uint64 lastVerifiedBatch, bytes32 newStateRoot, address aggregator) external;
```

### admin


```solidity
function admin() external returns (address);
```

