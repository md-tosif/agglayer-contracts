/* eslint-disable @typescript-eslint/no-shadow */
/* eslint-disable no-plusplus, no-await-in-loop */
import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';
import {
    PolygonZkEVMBridgeV2PessimisticMock,
    AgglayerBridgeL2FromEtrog,
    LegacyAgglayerGERL2,
    AgglayerGERL2,
} from '../../typechain-types';

describe('PolygonZkEVMBridgeV2Pessimistic upgrade -> AgglayerBridgeL2FromEtrog', () => {
    upgrades.silenceWarnings();

    let bridgeOldContract: PolygonZkEVMBridgeV2Pessimistic;
    let gerOldContract: LegacyAgglayerGERL2;
    let bridgeContract: AgglayerBridgeL2FromEtrog;
    let gerContract: AgglayerGERL2;

    const BRIDGE_SOVEREIGN_VERSION = 'v1.2.0';
    const GER_VERSION = 'v1.0.0';

    let rollupManager: any;
    let bridgeManager: any;
    let emergencyBridgePauser: any;
    let emergencyBridgeUnpauser: any;
    let proxiedTokensManager: any;
    let globalExitRootUpdater: any;
    let globalExitRootRemover: any;
    let beneficiary: any;

    const networkID = 1;

    beforeEach('Deploy contracts', async () => {
        // load signers
        [
            rollupManager,
            bridgeManager,
            emergencyBridgePauser,
            emergencyBridgeUnpauser,
            proxiedTokensManager,
            globalExitRootRemover,
            globalExitRootUpdater,
            beneficiary,
        ] = await ethers.getSigners();

        // deploy bridgeV2Pessimistic
        const bridgePessimisticFactory = await ethers.getContractFactory('PolygonZkEVMBridgeV2PessimisticMock');
        bridgeOldContract = (await upgrades.deployProxy(bridgePessimisticFactory, [], {
            initializer: false,
            unsafeAllow: ['constructor', 'missing-initializer', 'missing-initializer-call'],
        })) as unknown as PolygonZkEVMBridgeV2PessimisticMock;

        // deploy global exit root manager
        const PolygonZkEVMGlobalExitRootFactory = await ethers.getContractFactory('LegacyAgglayerGERL2');
        gerOldContract = (await upgrades.deployProxy(PolygonZkEVMGlobalExitRootFactory, [], {
            initializer: false,
            unsafeAllow: ['constructor', 'missing-initializer', 'missing-initializer-call'],
            constructorArgs: [bridgeOldContract.target],
        })) as unknown as LegacyAgglayerGERL2;

        // Initialize bridgeV2Pessimistic
        await bridgeOldContract.initialize(
            networkID,
            ethers.ZeroAddress, // zero for ether
            ethers.ZeroAddress, // zero for ether
            gerOldContract.target,
            rollupManager.address,
            '0x',
        );
    });

    it('Should upgrade and check params after upgrade from etrog to sovereign', async () => {
        const bridgeL2Factory = await ethers.getContractFactory('AgglayerBridgeL2FromEtrog');
        const balance = await ethers.provider.getBalance(bridgeOldContract);

        // Upgrade and initialize bridgeL2
        bridgeContract = (await upgrades.upgradeProxy(bridgeOldContract.target, bridgeL2Factory, {
            unsafeAllow: ['constructor', 'missing-initializer', 'missing-initializer-call'],
            call: {
                fn: 'initializeFromEtrog(address,address,address,address,address[],uint128)',
                args: [
                    bridgeManager.address,
                    emergencyBridgePauser.address,
                    emergencyBridgeUnpauser.address,
                    proxiedTokensManager.address,
                    [],
                    balance,
                ],
            },
        })) as unknown as AgglayerBridgeL2FromEtrog;

        const gerL2Factory = await ethers.getContractFactory('AgglayerGERL2');

        // Upgrade and initialize gerL2
        gerContract = (await upgrades.upgradeProxy(gerOldContract.target, gerL2Factory, {
            unsafeAllow: ['constructor', 'missing-initializer', 'missing-initializer-call'],
            constructorArgs: [bridgeContract.target],
            call: {
                fn: 'initialize(address,address)',
                args: [globalExitRootUpdater.address, globalExitRootRemover.address],
            },
        })) as unknown as AgglayerGERL2;

        // checks bridge
        expect(await bridgeContract.getProxiedTokensManager()).to.be.equal(proxiedTokensManager.address);
        expect(await bridgeContract.getWrappedTokenBridgeImplementation()).to.not.be.equal(ethers.ZeroAddress);
        expect(await bridgeContract.version()).to.equal(BRIDGE_SOVEREIGN_VERSION);
        expect(await bridgeContract.globalExitRootManager()).to.equal(gerContract.target);
        expect(await bridgeContract.polygonRollupManager()).to.equal(rollupManager);
        expect(await bridgeContract.emergencyBridgePauser()).to.equal(emergencyBridgePauser.address);
        expect(await bridgeContract.emergencyBridgeUnpauser()).to.equal(emergencyBridgeUnpauser.address);

        // checks ger
        expect(await gerContract.globalExitRootUpdater()).to.equal(globalExitRootUpdater.address);
        expect(await gerContract.globalExitRootRemover()).to.equal(globalExitRootRemover.address);
        expect(await gerContract.GER_SOVEREIGN_VERSION()).to.equal(GER_VERSION);
        expect(await gerContract.bridgeAddress()).to.equal(bridgeContract.target);
    });

    it('Should not allow to initialize again', async () => {
        await expect(
            bridgeContract.initializeFromEtrog(
                bridgeManager.address,
                emergencyBridgePauser.address,
                emergencyBridgeUnpauser.address,
                proxiedTokensManager.address,
                [],
                0,
            ),
        ).to.be.revertedWith('Initializable: contract is already initialized');
    });

    it('Should add wrapped token and upgrade with this token in LBT', async () => {
        const tokenWrappedFactory = await ethers.getContractFactory('TokenWrapped');
        await ethers.provider.send('hardhat_impersonateAccount', [bridgeOldContract.target]);
        await ethers.provider.send('hardhat_setBalance', [
            bridgeOldContract.target,
            `0x${ethers.parseUnits('2000', 18).toString(16)}`,
        ]);
        const bridgeSigner = await ethers.getSigner(bridgeOldContract.target as any);
        const tokenWrapped = await tokenWrappedFactory
            .connect(bridgeSigner)
            .deploy('name', 'symbol', '18', { gasPrice: 0 });
        const tokenWrappedAddress = await tokenWrapped.getAddress();

        // mint some tokens
        await tokenWrapped.connect(bridgeSigner).mint(beneficiary.address, ethers.parseUnits('1000', 18));
        const totalSupply = await tokenWrapped.totalSupply();
        expect(totalSupply).to.equal(ethers.parseUnits('1000', 18));
        await bridgeOldContract
            .connect(bridgeManager)
            .setMultipleSovereignTokenAddress([0], [tokenWrappedAddress], [tokenWrappedAddress], [false]);

        expect(await bridgeOldContract.wrappedTokenToTokenInfo(tokenWrappedAddress)).to.deep.equal([
            0,
            tokenWrappedAddress,
        ]);
        const bridgeL2Factory = await ethers.getContractFactory('AgglayerBridgeL2FromEtrog');
        const balance = await ethers.provider.getBalance(bridgeOldContract);

        // Upgrade and initialize bridgeL2
        bridgeContract = (await upgrades.upgradeProxy(bridgeOldContract.target, bridgeL2Factory, {
            unsafeAllow: ['constructor', 'missing-initializer', 'missing-initializer-call'],
            call: {
                fn: 'initializeFromEtrog(address,address,address,address,address[],uint128)',
                args: [
                    bridgeManager.address,
                    emergencyBridgePauser.address,
                    emergencyBridgeUnpauser.address,
                    proxiedTokensManager.address,
                    [tokenWrappedAddress],
                    balance,
                ],
            },
        })) as unknown as AgglayerBridgeL2FromEtrog;

        const gerL2Factory = await ethers.getContractFactory('AgglayerGERL2');

        // Upgrade and initialize gerL2
        gerContract = (await upgrades.upgradeProxy(gerOldContract.target, gerL2Factory, {
            unsafeAllow: ['constructor', 'missing-initializer', 'missing-initializer-call'],
            constructorArgs: [bridgeContract.target],
            call: {
                fn: 'initialize(address,address)',
                args: [globalExitRootUpdater.address, globalExitRootRemover.address],
            },
        })) as unknown as AgglayerGERL2;

        // checks bridge
        expect(await bridgeContract.getProxiedTokensManager()).to.be.equal(proxiedTokensManager.address);
        expect(await bridgeContract.getWrappedTokenBridgeImplementation()).to.not.be.equal(ethers.ZeroAddress);
        expect(await bridgeContract.version()).to.equal(BRIDGE_SOVEREIGN_VERSION);
        expect(await bridgeContract.globalExitRootManager()).to.equal(gerContract.target);
        expect(await bridgeContract.polygonRollupManager()).to.equal(rollupManager);
        expect(await bridgeContract.emergencyBridgePauser()).to.equal(emergencyBridgePauser.address);
        expect(await bridgeContract.emergencyBridgeUnpauser()).to.equal(emergencyBridgeUnpauser.address);
        expect(await bridgeContract.wrappedTokenToTokenInfo(tokenWrappedAddress)).to.deep.equal([
            0,
            tokenWrappedAddress,
        ]);
        const tokenInfoHash = ethers.solidityPackedKeccak256(['uint32', 'address'], [0, tokenWrappedAddress]);
        const amount = await bridgeContract.localBalanceTree(tokenInfoHash);
        expect(amount.toString()).to.equal(totalSupply.toString());

        // checks ger
        expect(await gerContract.globalExitRootUpdater()).to.equal(globalExitRootUpdater.address);
        expect(await gerContract.globalExitRootRemover()).to.equal(globalExitRootRemover.address);
        expect(await gerContract.GER_SOVEREIGN_VERSION()).to.equal(GER_VERSION);
        expect(await gerContract.bridgeAddress()).to.equal(bridgeContract.target);
    });
});
