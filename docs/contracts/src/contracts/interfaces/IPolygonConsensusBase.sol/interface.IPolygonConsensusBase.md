# IPolygonConsensusBase
[Git Source](https://github.com/agglayer/agglayer-contracts/blob/97cad9ab107727514c9d0cc64270f595a4c37f2c/contracts/interfaces/IPolygonConsensusBase.sol)


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

### admin


```solidity
function admin() external view returns (address);
```

## Errors
### AdminCannotBeZeroAddress
Thrown when trying to set the admin to the zero address


```solidity
error AdminCannotBeZeroAddress();
```

