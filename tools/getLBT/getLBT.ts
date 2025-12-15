import { ethers } from 'hardhat';
import fs from 'fs';
import path from 'path';
import parameters from './parameters.json';
import { logger } from '../../src/logger';
import { checkParams } from '../../src/utils';
import { fetchEventsInBatches, executeInBatches } from '../utils';
import { AgglayerBridge } from '../../typechain-types';

const DEFAULT_BLOCK_RANGE = 100000;
const DEFAULT_CONCURRENCY_LIMIT = 10;

async function main() {
    /*
     * Check parameters
     * Check that every necessary parameter is fulfilled
     */
    const mandatoryParameters = ['agglayerBridgeAddress'];
    checkParams(parameters, mandatoryParameters);

    const { agglayerBridgeAddress, options } = parameters;
    const dateStr = new Date().toISOString();

    // Get bridge instance
    const bridgeFactory = await ethers.getContractFactory('AgglayerBridge');
    const AgglayerBridge = bridgeFactory.attach(agglayerBridgeAddress) as AgglayerBridge;

    let blockNumber;
    if (options?.blockNumber && options.blockNumber !== 'latest') {
        blockNumber = parseInt(options.blockNumber, 10);
        if (isNaN(blockNumber) || blockNumber < 0) {
            throw new Error(`Invalid blockNumber: ${options.blockNumber}. Must be a non-negative number or "latest"`);
        }
    } else {
        blockNumber = await ethers.provider.getBlockNumber();
    }

    // //////////////////////////////
    //  Get events NewWrappedToken //
    // //////////////////////////////
    const blockRange = options?.blockRange || DEFAULT_BLOCK_RANGE;
    const concurrencyLimit = options?.concurrencyLimit || DEFAULT_CONCURRENCY_LIMIT;
    const events = [];
    logger.info(`Bridge address: ${agglayerBridgeAddress}`);

    if (options?.getEventsFromFile) {
        logger.info(`Getting events from file events.json`);
        const eventsFile = fs.readFileSync(path.join(__dirname, `events.json`), 'utf-8');
        const eventsJson = JSON.parse(eventsFile);
        events.push(...eventsJson);
    } else {
        logger.info(
            `Events fetching from block 0 to ${blockNumber} with blockRange ${blockRange} and concurrencyLimit ${concurrencyLimit}`,
        );

        // Create event filter
        const newWrappedTokenFilter = AgglayerBridge.filters.NewWrappedToken();

        // Fetch events in parallel batches
        const allResults = await fetchEventsInBatches(
            AgglayerBridge,
            newWrappedTokenFilter,
            blockRange,
            blockNumber,
            concurrencyLimit,
            'NewWrappedToken events',
        );

        logger.info(`Processing fetched events...`);
        // Process results in order
        // eslint-disable-next-line no-restricted-syntax
        for (const result of allResults) {
            const { events: fetchedEvents } = result;

            if (fetchedEvents.length > 0) {
                // eslint-disable-next-line no-restricted-syntax
                for (const event of fetchedEvents) {
                    events.push({
                        blockNumber: event.blockNumber.toString(),
                        originNetwork: event.args[0].toString(),
                        originTokenAddress: event.args[1],
                        wrappedTokenAddress: event.args[2],
                    });
                    logger.info(
                        `Block number: ${event.blockNumber.toString()} - wrappedTokenAddress: ${event.args[2]}`,
                    );
                }
            }
        }
    }

    logger.info(`Collecting totalSupply of every wrapped token (${events.length} tokens)...`);

    // Fetch totalSupply in parallel batches
    await executeInBatches(
        events,
        async (event) => {
            const { wrappedTokenAddress } = event;
            const contractToken = await ethers.getContractAt('TokenWrapped', wrappedTokenAddress);
            const totalSupply = await contractToken.totalSupply({ blockTag: blockNumber });
            event.totalSupply = totalSupply.toString();
        },
        concurrencyLimit,
        'Collecting totalSupply',
    );

    if (options?.printEvents) {
        fs.writeFileSync(path.join(__dirname, `events.json`), JSON.stringify(events, null, 2));
    }

    const tokenAddresses = [];
    const LBTObject = [] as any;

    // eslint-disable-next-line no-restricted-syntax
    for (const event of events) {
        tokenAddresses.push(event.wrappedTokenAddress);
        LBTObject.push({
            wrappedTokenAddress: event.wrappedTokenAddress,
            originNetwork: event.originNetwork,
            originTokenAddress: event.originTokenAddress,
            balance: event.totalSupply,
        });
    }

    // Get initial native supply
    const initNativeSupply = await ethers.provider.getBalance(agglayerBridgeAddress, 0);
    const currentNativeSupply = await ethers.provider.getBalance(agglayerBridgeAddress, blockNumber);
    const currentNativeUnlocked = initNativeSupply - currentNativeSupply;

    // Add native supply to LBT object
    LBTObject.push({
        wrappedTokenAddress: ethers.ZeroAddress,
        originNetwork: await AgglayerBridge.gasTokenNetwork(),
        originTokenAddress: await AgglayerBridge.gasTokenAddress(),
        balance: currentNativeUnlocked.toString(),
    });

    // Get WETH token address, this only works if the networks has a gas token
    const weth = await AgglayerBridge.WETHToken();
    if (weth !== ethers.ZeroAddress) {
        // Get WETH total supply
        const wethContract = await ethers.getContractAt('TokenWrapped', weth);
        const wethTotalSupply = await wethContract.totalSupply({ blockTag: blockNumber });

        LBTObject.push({
            wrappedTokenAddress: weth,
            originNetwork: 0, // ether
            originTokenAddress: ethers.ZeroAddress, // ether
            balance: wethTotalSupply.toString(),
        });
    }

    if (options?.printTokens) {
        const printObject = {
            initNativeSupply: initNativeSupply.toString(),
            tokenAddresses,
        };
        const writeTokensPath = options?.outputPathTokensArray
            ? path.join(__dirname, `../../${options.outputPathTokensArray}`)
            : path.join(__dirname, `WTokens-${dateStr}.json`);
        fs.writeFileSync(writeTokensPath, JSON.stringify(printObject, null, 2));
        logger.info(`File ${writeTokensPath} created`);
    }

    const writeLBTPath = options?.outputPathLBT
        ? path.join(__dirname, `../../${options.outputPathLBT}`)
        : path.join(__dirname, `initializeLBT-${dateStr}.json`);

    fs.writeFileSync(writeLBTPath, JSON.stringify(LBTObject, null, 2));
    logger.info(`File ${writeLBTPath} created`);
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});

/* eslint-disable no-extend-native */
Object.defineProperty(BigInt.prototype, 'toJSON', {
    get() {
        return () => String(this);
    },
});
