# IEmergencyManager
[Git Source](https://github.com/agglayer/agglayer-contracts/blob/97cad9ab107727514c9d0cc64270f595a4c37f2c/contracts/interfaces/IEmergencyManager.sol)


## Functions
### isEmergencyState

Returns whether the emergency state is active


```solidity
function isEmergencyState() external view returns (bool);
```

## Events
### EmergencyStateActivated
Emitted when emergency state is activated


```solidity
event EmergencyStateActivated();
```

### EmergencyStateDeactivated
Emitted when emergency state is deactivated


```solidity
event EmergencyStateDeactivated();
```

## Errors
### OnlyNotEmergencyState
Thrown when emergency state is active, and the function requires otherwise


```solidity
error OnlyNotEmergencyState();
```

### OnlyEmergencyState
Thrown when emergency state is not active, and the function requires otherwise


```solidity
error OnlyEmergencyState();
```

