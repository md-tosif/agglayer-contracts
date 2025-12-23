# VerifierRollupHelperMock
[Git Source](https://github.com/agglayer/agglayer-contracts/blob/97cad9ab107727514c9d0cc64270f595a4c37f2c/contracts/mocks/VerifierRollupHelperMock.sol)

**Inherits:**
[IVerifierRollup](/contracts/interfaces/IVerifierRollup.sol/interface.IVerifierRollup.md), [ISP1Verifier](/contracts/interfaces/ISP1Verifier.sol/interface.ISP1Verifier.md)


## Functions
### verifyProof


```solidity
function verifyProof(bytes32[24] calldata proof, uint256[1] memory pubSignals) public pure override returns (bool);
```

### verifyProof


```solidity
function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) public pure;
```

