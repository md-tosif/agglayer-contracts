/* eslint-disable no-await-in-loop, no-use-before-define, no-lonely-if */
/* eslint-disable no-console, no-inner-declarations, no-undef, import/no-unresolved */
import { expect } from 'chai';
import path = require('path');
import fs = require('fs');
import { ethers, upgrades } from 'hardhat';
import * as dotenv from 'dotenv';
import { logger } from '../../src/logger';
import { TimelockController } from '../../typechain-types';
import { genTimelockOperation, decodeScheduleData } from '../utils';
import { checkParams, getDeployerFromParameters, getProviderAdjustingMultiplierGas } from '../../src/utils';

import upgradeParameters from './upgrade_parameters.json';
import { addInfoOutput } from '../../tools/utils';

dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const pathOutputJson = path.join(__dirname, './upgrade_output.json');

async function main() {
    // Check for unsafe mode from parameters
    const isUnsafeMode = (upgradeParameters as any).unsafeMode || false;
    if (isUnsafeMode) {
        logger.warn('⚠️  UNSAFE MODE ENABLED: criticalTooling checks disabled');
    }

    let outputJson = {};
    // Add git info using addInfoOutput with criticalTooling flag
    outputJson = addInfoOutput(outputJson, !isUnsafeMode);

    /*
     * Check upgrade parameters
     * Check that every necessary parameter is fulfilled
     */
    const mandatoryUpgradeParameters = ['bridgeL2Address'];
    checkParams(upgradeParameters, mandatoryUpgradeParameters);

    const { bridgeL2Address } = upgradeParameters;
    const salt = (upgradeParameters as any).timelockSalt || ethers.ZeroHash;

    // Load provider
    const currentProvider = getProviderAdjustingMultiplierGas(upgradeParameters, ethers);

    // Load deployer
    const deployer = await getDeployerFromParameters(currentProvider, upgradeParameters, ethers);
    logger.info(`Deploying implementation with: ${deployer.address}`);

    // get proxy admin and timelock
    logger.info('Get proxy admin information');
    // Get proxy admin
    const proxyAdmin = await upgrades.admin.getInstance();

    // Assert correct admin
    expect(await upgrades.erc1967.getAdminAddress(bridgeL2Address as string)).to.be.equal(proxyAdmin.target);

    // Get timelock address
    const timelockAddress = await proxyAdmin.owner();

    // load timelock
    const timelockContractFactory = await ethers.getContractFactory('PolygonZkEVMTimelock', deployer);
    const timelockContract = (await timelockContractFactory.attach(timelockAddress)) as TimelockController;
    // take params delay, or minimum timelock delay
    const timelockDelay = (upgradeParameters as any).timelockDelay || (await timelockContract.getMinDelay());

    // Upgrade AgglayerBridge -> AgglayerBridgeL2
    const newBridgeFactory = await ethers.getContractFactory('AgglayerBridgeL2', deployer);
    const impBridgeAddress = await upgrades.prepareUpgrade(bridgeL2Address, newBridgeFactory, {
        unsafeAllow: ['constructor', 'missing-initializer', 'missing-initializer-call'],
    });

    logger.info('#######################\n');
    logger.info(`Polygon sovereign bridge implementation deployed at: ${impBridgeAddress}`);

    // Create schedule and execute operation
    logger.info('Create schedule and execute operation');
    logger.info('Operation Bridge');

    const operationBridge = genTimelockOperation(
        proxyAdmin.target,
        0, // value
        proxyAdmin.interface.encodeFunctionData('upgrade', [bridgeL2Address, impBridgeAddress]), // data
        ethers.ZeroHash, // predecessor
        salt, // salt
    );

    logger.info('scheduleData & executeData');
    // Schedule operation
    const scheduleData = timelockContractFactory.interface.encodeFunctionData('schedule', [
        operationBridge.target,
        operationBridge.value,
        operationBridge.data,
        operationBridge.predecessor, // predecessor
        operationBridge.salt, // salt
        timelockDelay,
    ]);

    // Execute operation
    const executeData = timelockContractFactory.interface.encodeFunctionData('execute', [
        operationBridge.target,
        operationBridge.value,
        operationBridge.data,
        operationBridge.predecessor, // predecessor
        operationBridge.salt, // salt
    ]);

    logger.info({ scheduleData });
    logger.info({ executeData });

    // Get current block number, used in the shallow fork tests
    const blockNumber = await ethers.provider.getBlockNumber();
    outputJson = {
        ...outputJson,
        scheduleData,
        executeData,
        timelockContractAddress: timelockAddress,
        implementationDeployBlockNumber: blockNumber,
        bridgeImplementationAddress: impBridgeAddress,
        inputs: {
            bridgeL2Address,
            timelockDelay,
            salt,
        },
    };

    // Decode the scheduleData for better readability
    const objectDecoded = await decodeScheduleData(scheduleData, proxyAdmin);
    (outputJson as any).decodedScheduleData = objectDecoded;

    fs.writeFileSync(pathOutputJson, JSON.stringify(outputJson, null, 1));
    logger.info(`Output saved to: ${pathOutputJson}`);
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
