# AgglayerGERMock
[Git Source](https://github.com/agglayer/agglayer-contracts/blob/97cad9ab107727514c9d0cc64270f595a4c37f2c/contracts/mocks/AgglayerGERMock.sol)

**Inherits:**
[AgglayerGER](/contracts/AgglayerGER.sol/contract.AgglayerGER.md)

AgglayerManager mock


## Functions
### constructor


```solidity
constructor(address _rollupManager, address _bridgeAddress) AgglayerGER(_rollupManager, _bridgeAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_rollupManager`|`address`|Rollup manager contract address|
|`_bridgeAddress`|`address`|PolygonZkEVMBridge contract address|


### injectGER


```solidity
function injectGER(bytes32 _root, uint32 depositCount) external;
```

