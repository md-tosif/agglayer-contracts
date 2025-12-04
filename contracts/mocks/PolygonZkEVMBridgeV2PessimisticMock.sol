pragma solidity 0.8.20;

import "../previousVersions/pessimistic/PolygonZkEVMBridgeV2Pessimistic.sol";

// Contract created to perform the upgrade from the Etrog version to the AgglayerBridgeL2 version.
contract PolygonZkEVMBridgeV2PessimisticMock is
    PolygonZkEVMBridgeV2Pessimistic
{
    function setMultipleSovereignTokenAddress(
        uint32[] memory originNetworks,
        address[] memory originTokenAddresses,
        address[] memory sovereignTokenAddresses,
        bool[] memory sovereignTokenAddressIsNotMintable
    ) public {
        // Make multiple calls to setSovereignTokenAddress
        for (uint256 i = 0; i < sovereignTokenAddresses.length; i++) {
            uint32 originNetwork = originNetworks[i];
            address originTokenAddress = originTokenAddresses[i];
            address sovereignTokenAddress = sovereignTokenAddresses[i];
            bool isNotMintable = sovereignTokenAddressIsNotMintable[i];

            // Compute token info hash
            bytes32 tokenInfoHash = keccak256(
                abi.encodePacked(originNetwork, originTokenAddress)
            );
            // Set the address of the wrapper
            tokenInfoToWrappedToken[tokenInfoHash] = sovereignTokenAddress;
            // Set the token info mapping
            // @note wrappedTokenToTokenInfo mapping is not overwritten while tokenInfoToWrappedToken it is
            wrappedTokenToTokenInfo[sovereignTokenAddress] = TokenInformation(
                originNetwork,
                originTokenAddress
            );
        }
    }
}
