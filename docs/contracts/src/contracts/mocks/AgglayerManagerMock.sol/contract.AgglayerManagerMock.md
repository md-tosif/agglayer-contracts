# AgglayerManagerMock
[Git Source](https://github.com/agglayer/agglayer-contracts/blob/97cad9ab107727514c9d0cc64270f595a4c37f2c/contracts/mocks/AgglayerManagerMock.sol)

**Inherits:**
[AgglayerManager](/contracts/AgglayerManager.sol/contract.AgglayerManager.md)

AgglayerManager mock


## Functions
### constructor


```solidity
constructor(
    IAgglayerGER _globalExitRootManager,
    IERC20Upgradeable _pol,
    IPolygonZkEVMBridge _bridgeAddress,
    IAgglayerGateway _aggLayerGateway
) AgglayerManager(_globalExitRootManager, _pol, _bridgeAddress, _aggLayerGateway);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_globalExitRootManager`|`IAgglayerGER`|Global exit root manager address|
|`_pol`|`IERC20Upgradeable`|MATIC token address|
|`_bridgeAddress`|`IPolygonZkEVMBridge`|Bridge address|
|`_aggLayerGateway`|`IAgglayerGateway`||


### initializeMock


```solidity
function initializeMock(
    address trustedAggregator,
    // uint64 _pendingStateTimeout,
    // uint64 _trustedAggregatorTimeout,
    address admin,
    address timelock,
    address emergencyCouncil
)
    external
    reinitializer(4);
```

### prepareMockCalculateRoot


```solidity
function prepareMockCalculateRoot(bytes32[] memory localExitRoots) public;
```

### exposed_checkStateRootInsidePrime


```solidity
function exposed_checkStateRootInsidePrime(uint256 newStateRoot) public pure returns (bool);
```

### setRollupData


```solidity
function setRollupData(uint32 rollupID, bytes32 lastLocalExitRoot, bytes32 lastPessimisticRoot) external;
```

