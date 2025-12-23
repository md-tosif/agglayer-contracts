# AgglayerManagerNotUpgraded
[Git Source](https://github.com/agglayer/agglayer-contracts/blob/97cad9ab107727514c9d0cc64270f595a4c37f2c/contracts/newDeployments/AgglayerManagerNotUpgraded.sol)

**Inherits:**
[AgglayerManager](/contracts/AgglayerManager.sol/contract.AgglayerManager.md)

AgglayerManager Test


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


### initialize


```solidity
function initialize(address trustedAggregator, address admin, address timelock, address emergencyCouncil)
    external
    reinitializer(5);
```

