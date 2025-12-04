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
     * @param initNativeSupply init bridge ETH amount (max = 2^128 - 1). This parameter is necessary because not all bridges have the same initial amount.
     */
    function initializeFromEtrog(
        address _bridgeManager,
        address _emergencyBridgePauser,
        address _emergencyBridgeUnpauser,
        address _proxiedTokensManager,
        address[] memory wrappedTokensAddresses,
        uint128 initNativeSupply
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

        _initializeLBT(wrappedTokensAddresses, initNativeSupply);
    }

    /**
     * @dev Builds origin network/address/amount arrays from token addresses (index 0 = native token) and sets the Local Balance Tree.
     * @param wrappedTokensAddresses Array of wrapped-token contract addresses to include; internal arrays reserve index 0 for the native token, so wrapped-token data is mapped starting at index 1.
     * @param initNativeSupply Initial supply used to compute the native token amount when WETHToken is unset
     */
    function _initializeLBT(
        address[] memory wrappedTokensAddresses,
        uint256 initNativeSupply
    ) internal {
        uint256 amountWETH;
        // If WETHToken is address(0), gas token will be ether
        // The amount in LBT is computed as contract init amount - contract ETH balance
        // else, we read WETH total supply
        if (address(WETHToken) == address(0)) {
            uint256 balance = address(this).balance;
            require(
                initNativeSupply >= balance,
                "initNativeSupply < ETH balance"
            );
            amountWETH = initNativeSupply - balance;
        } else {
            amountWETH = ITokenWrappedBridgeUpgradeable(address(WETHToken))
                .totalSupply();
            // In the case where the gas token is not ether, we set gas token amount to contract balance
            uint256 gasTokenAmount = address(this).balance;
            _setLocalBalanceTree(
                gasTokenNetwork,
                gasTokenAddress,
                gasTokenAmount
            );
        }

        // Set native token (ETH or WETH) amount
        _setLocalBalanceTree(0, address(0), amountWETH);

        // Set all the other wrapped tokens amounts
        for (uint256 i = 0; i < wrappedTokensAddresses.length; i++) {
            address wrapped = wrappedTokensAddresses[i];
            TokenInformation memory tokenInfo = wrappedTokenToTokenInfo[
                wrapped
            ];

            uint32 originNetwork = tokenInfo.originNetwork;
            address originTokenAddress = tokenInfo.originTokenAddress;
            uint256 amount = ITokenWrappedBridgeUpgradeable(address(wrapped))
                .totalSupply();

            _setLocalBalanceTree(originNetwork, originTokenAddress, amount);
        }
    }
}
