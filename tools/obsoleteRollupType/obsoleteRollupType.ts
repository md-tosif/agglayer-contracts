/* eslint-disable no-await-in-loop, no-use-before-define, no-lonely-if, no-inner-declarations, no-undef, import/no-unresolved, import/extensions */
import path = require('path');
import fs = require('fs');

import * as dotenv from 'dotenv';
import { ethers, network } from 'hardhat';
import { AgglayerManager } from '../../typechain-types';
import { transactionTypes, genOperation } from '../utils';
import '../../deployment/helpers/utils';
import { OBSOLETE_ROLLUP_TYPE_ROLE } from '../../src/constants';
import { logger } from '../../src/logger';
import { checkParams, getProviderAdjustingMultiplierGas, getDeployerFromParameters } from '../../src/utils';
import obsoleteRollupTypesParameters from './obsoleteRollupType.json';

dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const dateStr = new Date().toISOString();
const pathOutputJson = path.join(__dirname, `./obsoleteRollupTypeOutput-${dateStr}.json`);

async function main() {
    /*
     * Check parameters
     * Check that every necessary parameter is fullfilled
     */
    const mandatoryDeploymentParameters = ['type', 'agglayerManagerAddress'];

    // check create rollup type
    switch (obsoleteRollupTypesParameters.type) {
        case transactionTypes.EOA:
        case transactionTypes.MULTISIG:
            break;
        case transactionTypes.TIMELOCK:
            mandatoryDeploymentParameters.push('timelockDelay');
            break;
        default:
            throw new Error(`Invalid type ${obsoleteRollupTypesParameters.type}`);
    }

    checkParams(obsoleteRollupTypesParameters, mandatoryDeploymentParameters);

    logger.info(`Starting script to obsolete rollup types from ${obsoleteRollupTypesParameters.type}`);

    // Determine which input mode is being used
    const paramsWithObsoleteTypes = obsoleteRollupTypesParameters as any;
    const hasObsoleteRollupTypes = paramsWithObsoleteTypes.obsoleteRollupTypes !== undefined;
    const hasExcludedRollupTypes = paramsWithObsoleteTypes.excludedRollupTypesID !== undefined;

    if (!hasObsoleteRollupTypes && !hasExcludedRollupTypes) {
        throw new Error('Must provide either "obsoleteRollupTypes" or "excludedRollupTypesID" in the configuration');
    }

    if (hasObsoleteRollupTypes && hasExcludedRollupTypes) {
        throw new Error('Cannot provide both "obsoleteRollupTypes" and "excludedRollupTypesID". Use only one.');
    }

    // Load provider
    const currentProvider = getProviderAdjustingMultiplierGas(obsoleteRollupTypesParameters, ethers);

    // Load deployer
    const deployer = await getDeployerFromParameters(currentProvider, obsoleteRollupTypesParameters, ethers);
    logger.info(`Using deployer: ${deployer.address}`);

    const { agglayerManagerAddress } = obsoleteRollupTypesParameters;

    // Load Rollup manager
    const AgglayerManagerFactory = await ethers.getContractFactory('AgglayerManager', deployer);
    const rollupManagerContract = AgglayerManagerFactory.attach(agglayerManagerAddress) as AgglayerManager;

    let rollupTypesToObsolete: number[] = [];

    if (hasObsoleteRollupTypes) {
        // Mode 1: Direct list of rollup types to obsolete
        logger.info('Mode: Direct list of rollup types to obsolete');
        rollupTypesToObsolete = paramsWithObsoleteTypes.obsoleteRollupTypes;

        if (rollupTypesToObsolete.length === 0) {
            throw new Error('No rollup types to obsolete');
        }

        logger.info('Checking if any rollup types are already obsolete...');
        for (let i = 0; i < rollupTypesToObsolete.length; i++) {
            const rollupTypeID = rollupTypesToObsolete[i];
            try {
                const rollupType = await rollupManagerContract.rollupTypeMap(rollupTypeID);
                if (rollupType.obsolete) {
                    logger.error(`ERROR: Rollup type ${rollupTypeID} is already obsolete!`);
                    process.exit(1);
                }
                logger.info(`✓ Rollup type ${rollupTypeID} is not obsolete`);
            } catch (e) {
                logger.error(`ERROR: Failed to check rollup type ${rollupTypeID}:`, e);
                process.exit(1);
            }
        }
        logger.info('All rollup types are valid and not obsolete.\n');
    } else {
        // Mode 2: Exclude specified rollup types, obsolete all others
        logger.info('Mode: Obsolete all rollup types except excluded ones');
        const excludedRollupTypesID = paramsWithObsoleteTypes.excludedRollupTypesID;

        // Get the total number of rollup types
        logger.info('Fetching all rollup types from AgglayerManager...');
        const rollupTypeCount = await rollupManagerContract.rollupTypeCount();
        logger.info(`Total rollup types count: ${rollupTypeCount}`);

        const excludedSet = new Set(excludedRollupTypesID);
        logger.info(`Excluded rollup types: [${Array.from(excludedSet).join(', ')}]`);
        logger.info('Scanning rollup types...');

        for (let i = 1; i <= rollupTypeCount; i++) {
            const rollupTypeID = i;

            try {
                const rollupType = await rollupManagerContract.rollupTypeMap(rollupTypeID);

                if (rollupType.obsolete) {
                    logger.info(`  Rollup type ${rollupTypeID}: Already obsolete (skipping)`);
                    continue;
                }

                if (excludedSet.has(rollupTypeID)) {
                    logger.info(`  Rollup type ${rollupTypeID}: In excluded list (skipping)`);
                    continue;
                }

                logger.info(`  Rollup type ${rollupTypeID}: Will be obsoleted`);
                rollupTypesToObsolete.push(rollupTypeID);
            } catch (e) {
                logger.warn(`  Rollup type ${rollupTypeID}: Failed to fetch (skipping)`, e);
            }
        }

        logger.info(`\nTotal rollup types to obsolete: ${rollupTypesToObsolete.length}`);
        logger.info(`Rollup types to obsolete: [${rollupTypesToObsolete.join(', ')}]\n`);

        if (rollupTypesToObsolete.length === 0) {
            logger.info('No rollup types to obsolete. Exiting.');
            return;
        }
    }

    const outputsJson = [] as any;

    // Timelock vars
    const operations = {} as any;
    operations.target = [];
    operations.value = [];
    operations.data = [];
    const predecessor = ethers.ZeroHash;
    const salt = (obsoleteRollupTypesParameters as any).timelockSalt || ethers.ZeroHash;

    for (let i = 0; i < rollupTypesToObsolete.length; i++) {
        const outputJson = {} as any;
        const rollupTypeID = rollupTypesToObsolete[i];

        outputJson.networkName = network.name;
        outputJson.agglayerManagerAddress = agglayerManagerAddress;
        outputJson.rollupTypeID = rollupTypeID;

        if (obsoleteRollupTypesParameters.type === transactionTypes.EOA) {
            // Check role
            if ((await rollupManagerContract.hasRole(OBSOLETE_ROLLUP_TYPE_ROLE, deployer.address)) === false) {
                // log that address has no role
                throw new Error(`Address ${deployer.address} does not have the OBSOLETE_ROLLUP_TYPE_ROLE role`);
            }
            logger.info(`Obsoleting rollup type ${rollupTypeID}...`);
            try {
                const tx = await rollupManagerContract.obsoleteRollupType(rollupTypeID);
                const receipt = await tx.wait();
                if (receipt) {
                    logger.info(`Transaction hash: ${receipt.hash}`);
                }
                outputJson.successObsolete = true;
            } catch (e) {
                outputJson.successObsolete = false;
                logger.error(`Error obsoleting rollup type ${rollupTypeID}`);
                logger.error(e);
            }
        } else if (obsoleteRollupTypesParameters.type === transactionTypes.TIMELOCK) {
            logger.info(`Creating timelock txs for obsolete rollup type ${rollupTypeID}...`);
            const operation = genOperation(
                agglayerManagerAddress,
                0, // value
                AgglayerManagerFactory.interface.encodeFunctionData('obsoleteRollupType', [rollupTypeID]),
                predecessor, // predecessor
                salt, // salt
            );
            operations.target.push(operation.target);
            operations.value.push(operation.value);
            operations.data.push(operation.data);
        } else {
            logger.info(`Creating calldata for obsolete rollup type from multisig ${rollupTypeID}...`);
            const txObsoleteRollupType = AgglayerManagerFactory.interface.encodeFunctionData('obsoleteRollupType', [
                rollupTypeID,
            ]);
            outputJson.txObsoleteRollupType = txObsoleteRollupType;
        }
        outputsJson.push(outputJson);
    }

    // if type === Timelock --> get scheduleData & executeData
    if (obsoleteRollupTypesParameters.type === transactionTypes.TIMELOCK) {
        logger.info(`Build scheduleData & executeData`);
        const { timelockDelay } = obsoleteRollupTypesParameters;
        // load timelock
        const timelockContractFactory = await ethers.getContractFactory('PolygonZkEVMTimelock', deployer);

        // Schedule operation
        const scheduleData = timelockContractFactory.interface.encodeFunctionData('scheduleBatch', [
            operations.target,
            operations.value,
            operations.data,
            predecessor,
            salt,
            timelockDelay,
        ]);

        // Execute operation
        const executeData = timelockContractFactory.interface.encodeFunctionData('executeBatch', [
            operations.target,
            operations.value,
            operations.data,
            predecessor,
            salt,
        ]);

        // Decode the scheduleData for better readibility
        const timelockTx = timelockContractFactory.interface.parseTransaction({
            data: scheduleData,
        });
        const paramsArray = timelockTx?.fragment.inputs;
        const objectDecoded: any = {};

        for (let i = 0; i < (paramsArray?.length || 0); i++) {
            const currentParam = paramsArray![i];
            objectDecoded[currentParam.name] = timelockTx?.args[i];

            if (currentParam.name === 'payloads') {
                // for each payload
                const payloads = timelockTx?.args[i];
                for (let j = 0; j < payloads.length; j++) {
                    const data = payloads[j];
                    const decodedAgglayerManager = AgglayerManagerFactory.interface.parseTransaction({
                        data,
                    });

                    const resultDecodeAgglayerManager: any = {};
                    resultDecodeAgglayerManager.signature = decodedAgglayerManager?.signature;
                    resultDecodeAgglayerManager.selector = decodedAgglayerManager?.selector;

                    const paramsArrayData = decodedAgglayerManager?.fragment.inputs;

                    for (let n = 0; n < (paramsArrayData?.length || 0); n++) {
                        const currentParamData = paramsArrayData![n];
                        resultDecodeAgglayerManager[currentParamData.name] = decodedAgglayerManager?.args[n];
                    }
                    objectDecoded[`decodePayload_${j}`] = resultDecodeAgglayerManager;
                }
            }
        }
        const outputTimelock = {
            rollupTypes: outputsJson,
            scheduleData,
            executeData,
            decodeScheduleData: objectDecoded,
        };

        fs.writeFileSync(pathOutputJson, JSON.stringify(outputTimelock, null, 1));
    } else {
        fs.writeFileSync(pathOutputJson, JSON.stringify(outputsJson, null, 1));
    }

    logger.info(`Finished script, output saved at: ${pathOutputJson}`);
}

main().catch((e) => {
    logger.error(e);
    process.exit(1);
});
