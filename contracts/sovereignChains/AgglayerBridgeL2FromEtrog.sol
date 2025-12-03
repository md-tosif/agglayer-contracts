pragma solidity 0.8.28;

import "./AgglayerBridgeL2.sol";
import {ITokenWrappedBridgeUpgradeable} from "../interfaces/ITokenWrappedBridgeUpgradeable.sol";

// Contract created to perform the upgrade from the Etrog version to the AgglayerBridgeL2 version.
contract AgglayerBridgeL2FromEtrog is AgglayerBridgeL2 {
    /**
     * @dev Thrown when one of the initialization parameters that must be 0 has already been initialized
     */
    error ParameterAlreadyInitialized();

    /**
     * @notice Override the function to prevent the contract from being initialized with this initializer
     */
    function initialize(
        uint32, // _networkID
        address, // _gasTokenAddress
        uint32, // _gasTokenNetwork
        IBaseLegacyAgglayerGER, // _globalExitRootManager
        address, // _polygonRollupManager
        bytes memory, // _gasTokenMetadata
        address, // _bridgeManager
        address, // _sovereignWETHAddress
        bool, // _sovereignWETHAddressIsNotMintable
        address, // _emergencyBridgePauser
        address, // _emergencyBridgeUnpauser
        address // _proxiedTokensManager
    ) public virtual override(AgglayerBridgeL2) initializer {
        revert InvalidInitializeFunction();
    }

    /**
     * @dev initializer function to set the initial values when the contract is upgraded from the Etrog version
     * @param _bridgeManager bridge manager address
     * @param _emergencyBridgePauser emergency bridge pauser address, allowed to be zero if the chain wants to disable the feature to stop the bridge
     * @param _emergencyBridgeUnpauser emergency bridge unpauser address, allowed to be zero if the chain wants to disable the feature to unpause the bridge
     * @param _proxiedTokensManager address of the proxied tokens manager
     * @param wrappedTokensAddresses array of wrapped tokens
     * @param initSupply init bridge ETH amount (max = 2^128 - 1). This parameter is necessary because not all bridges have the same initial amount.
     */
    function initializeFromEtrog(
        address _bridgeManager,
        address _emergencyBridgePauser,
        address _emergencyBridgeUnpauser,
        address _proxiedTokensManager,
        address[] memory wrappedTokensAddresses,
        uint128 initSupply
    ) public virtual getInitializedVersion reinitializer(3) {
        // Checks that upgrade is being done from the contract initialized
        if (_initializerVersion == 0) {
            revert InvalidInitializeFunction();
        }

        // Checks that the new parameters are not already set
        if (
            bridgeManager != address(0) ||
            emergencyBridgePauser != address(0) ||
            emergencyBridgeUnpauser != address(0) ||
            proxiedTokensManager != address(0)
        ) {
            revert ParameterAlreadyInitialized();
        }

        // Set bridge manager
        bridgeManager = _bridgeManager;

        // Set emergency bridge pauser and unpauser
        emergencyBridgePauser = _emergencyBridgePauser;
        emit AcceptEmergencyBridgePauserRole(address(0), emergencyBridgePauser);
        emergencyBridgeUnpauser = _emergencyBridgeUnpauser;
        emit AcceptEmergencyBridgeUnpauserRole(
            address(0),
            emergencyBridgeUnpauser
        );

        // Set proxied tokens manager
        require(
            _proxiedTokensManager != address(this),
            BridgeAddressNotAllowed()
        );

        // It's not allowed proxiedTokensManager to be zero address. If disabling token upgradability is required, add a not owned account like 0xffff...fffff
        require(_proxiedTokensManager != address(0), InvalidZeroAddress());
        proxiedTokensManager = _proxiedTokensManager;
        emit AcceptProxiedTokensManagerRole(address(0), proxiedTokensManager);

        _setLBTFromTokensAddress(wrappedTokensAddresses, initSupply);
    }

    /**
     * @dev Builds origin network/address/amount arrays from token addresses (index 0 = native token) and sets the Local Balance Tree.
     * @param wrappedTokensAddresses Array of wrapped-token contract addresses to include; internal arrays reserve index 0 for the native token, so wrapped-token data is mapped starting at index 1.
     * @param initSupply Initial supply used to compute the native token amount when WETHToken is unset
     */
    function _setLBTFromTokensAddress(
        address[] memory wrappedTokensAddresses,
        uint256 initSupply
    ) internal {
        uint256 len = wrappedTokensAddresses.length + 1; // + 1 --> WETH token
        uint32[] memory originNetworkArray = new uint32[](len);
        address[] memory originTokenAddressArray = new address[](len);
        uint256[] memory amountArray = new uint256[](len);

        originNetworkArray[0] = 0;
        originTokenAddressArray[0] = address(0);

        if (address(WETHToken) == address(0)) {
            uint256 balance = address(this).balance;
            require(initSupply >= balance, "initSupply < ETH balance");
            amountArray[0] = initSupply - balance;
        } else {
            amountArray[0] = ITokenWrappedBridgeUpgradeable(address(WETHToken))
                .totalSupply();
        }

        for (uint256 i = 1; i < len; i++) {
            address wrapped = wrappedTokensAddresses[i];
            TokenInformation memory tokenInfo = wrappedTokenToTokenInfo[wrapped];

            originNetworkArray[i] = tokenInfo.originNetwork;
            originTokenAddressArray[i] = tokenInfo.originTokenAddress;
            amountArray[i] = ITokenWrappedBridgeUpgradeable(wrapped).totalSupply();
        }

        _setLocalBalanceTree(
            originNetworkArray,
            originTokenAddressArray,
            amountArray
        );
    }
}
