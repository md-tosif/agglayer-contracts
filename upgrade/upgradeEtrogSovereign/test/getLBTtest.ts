import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';
import { logger } from '../../../src/logger';

export async function getLBTFork(
    bridgeAddress: string,
    blockNumber?: number,
): Promise<{ tokensPath: string; lbtPath: string }> {
    const rootDir = path.join(__dirname, '../../../');
    const getLBTDir = path.join(rootDir, 'tools', 'getLBT');
    const parametersPath = path.join(getLBTDir, 'parameters.json');
    const backupPath = path.join(getLBTDir, 'parameters.json.bak');

    // Directory where we want the getLBT output to be placed: this test directory
    // Path is relative to project root (getLBT.ts resolves it from tools/getLBT directory)
    const tokensFilePath = 'upgrade/upgradeEtrogSovereign/test/tokens.json';
    const lbtFilePath = 'upgrade/upgradeEtrogSovereign/test/LBT.json';

    let hadBackup = false;

    try {
        // backup existing parameters.json if it exists
        if (fs.existsSync(parametersPath)) {
            fs.copyFileSync(parametersPath, backupPath);
            hadBackup = true;
            logger.info('Backed up existing parameters.json -> parameters.json.bak');
        }

        // set parameters for this test - generate both tokens.json and LBT.json
        const params = {
            agglayerBridgeAddress: bridgeAddress,
            options: {
                blockRange: 1000,
                printEvents: false,
                printTokens: true,
                getEventsFromFile: false,
                concurrencyLimit: 100,
                outputPathTokensArray: tokensFilePath,
                outputPathLBT: lbtFilePath,
                blockNumber: blockNumber || 'latest',
            },
        };

        fs.writeFileSync(parametersPath, JSON.stringify(params, null, 2));
        logger.info(
            'Wrote temporary parameters.json with outputPathTokensArray =',
            tokensFilePath,
            'and outputPathLBT =',
            lbtFilePath,
        );

        // run the getLBT tool with --network localhost
        // Using npx hardhat run tools/getLBT/getLBT.ts --network localhost
        logger.info(`Running getLBT tool with --network custom in block number ${blockNumber}...`);
        const cmd = 'npx';
        const args = ['hardhat', 'run', path.join(rootDir, 'tools', 'getLBT', 'getLBT.ts'), '--network', 'custom'];
        const result = spawnSync(cmd, args, { stdio: 'inherit', cwd: __dirname, shell: false });

        if (result.error) {
            throw result.error;
        }

        if (result.status !== 0) {
            throw new Error(`getLBT tool exited with code ${result.status}`);
        }
        logger.info('getLBT tool completed successfully');
    } catch (err) {
        console.error('Error during getLBT test script:', err);
        process.exitCode = 1;
    } finally {
        // restore backup if needed
        try {
            if (hadBackup && fs.existsSync(backupPath)) {
                fs.copyFileSync(backupPath, parametersPath);
                fs.unlinkSync(backupPath);
                logger.info('Restored original parameters.json from backup');
            } else if (!hadBackup && fs.existsSync(parametersPath)) {
                // remove the temporary parameters.json we created
                fs.unlinkSync(parametersPath);
                logger.info('Removed temporary parameters.json');
            }
        } catch (restoreErr) {
            console.error('Failed to restore original parameters.json:', restoreErr);
            process.exitCode = 2;
        }
    }
    return { tokensPath: tokensFilePath, lbtPath: lbtFilePath };
}
