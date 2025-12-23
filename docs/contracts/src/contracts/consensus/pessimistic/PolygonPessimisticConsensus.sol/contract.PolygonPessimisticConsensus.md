# PolygonPessimisticConsensus
[Git Source](https://github.com/agglayer/agglayer-contracts/blob/97cad9ab107727514c9d0cc64270f595a4c37f2c/contracts/consensus/pessimistic/PolygonPessimisticConsensus.sol)

**Inherits:**
[PolygonConsensusBase](/contracts/lib/PolygonConsensusBase.sol/abstract.PolygonConsensusBase.md), [IPolygonPessimisticConsensus](/contracts/interfaces/IPolygonPessimisticConsensus.sol/interface.IPolygonPessimisticConsensus.md)


## State Variables
### CONSENSUS_TYPE

```solidity
uint32 public constant CONSENSUS_TYPE = 0
```


### _legacyDataAvailabilityProtocol
**Note:**
oz-renamed-from: dataAvailabilityProtocol


```solidity
address private _legacyDataAvailabilityProtocol
```


### _legacyIsSequenceWithDataAvailabilityAllowed
**Note:**
oz-renamed-from: isSequenceWithDataAvailabilityAllowed


```solidity
bool private _legacyIsSequenceWithDataAvailabilityAllowed
```


## Functions
### constructor


```solidity
constructor(
    IAgglayerGER _globalExitRootManager,
    IERC20Upgradeable _pol,
    IAgglayerBridge _bridgeAddress,
    AgglayerManager _rollupManager
) PolygonConsensusBase(_globalExitRootManager, _pol, _bridgeAddress, _rollupManager);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_globalExitRootManager`|`IAgglayerGER`|Global exit root manager address|
|`_pol`|`IERC20Upgradeable`|POL token address|
|`_bridgeAddress`|`IAgglayerBridge`|Bridge address|
|`_rollupManager`|`AgglayerManager`|Rollup manager address|


### getConsensusHash

Note Return the necessary consensus information for the proof hashed


```solidity
function getConsensusHash() public view returns (bytes32);
```

