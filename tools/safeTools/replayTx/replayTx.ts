/* eslint-disable no-console */
import { ethers, config } from 'hardhat';
import { HttpNetworkConfig } from 'hardhat/types';

// ============== CONFIGURATION ==============
// Source: network name from hardhat.config.ts (where the original tx was executed)
const SOURCE_NETWORK = 'sepolia';

// Target: network where we want to replay the tx (uses --network flag)
// Run with: npx hardhat run tools/safeTools/replayTx/replayTx.ts --network <target_network>

// Transaction hash to replay
const TX_HASH = '0xb5ea73627e2f671b7414c66b2e85b916a8f1e081c0acce59f8ae80ff48f16c23';
// ============================================

async function main() {
    console.log('='.repeat(60));
    console.log('Replay Transaction Script');
    console.log('='.repeat(60));

    // Get source network RPC from hardhat config
    const sourceNetworkConfig = config.networks[SOURCE_NETWORK] as HttpNetworkConfig;
    if (!sourceNetworkConfig || !sourceNetworkConfig.url) {
        throw new Error(`Network "${SOURCE_NETWORK}" not found in hardhat.config.ts or has no URL`);
    }
    const sourceRpc = sourceNetworkConfig.url;
    console.log(`\nSource network: ${SOURCE_NETWORK} (${sourceRpc})`);

    // Create provider for source network
    const sourceProvider = new ethers.JsonRpcProvider(sourceRpc);

    // Get the original transaction
    console.log(`\nFetching tx from source: ${TX_HASH}`);
    const tx = await sourceProvider.getTransaction(TX_HASH);

    if (!tx) {
        throw new Error(`Transaction ${TX_HASH} not found on source network`);
    }

    console.log('\n--- Original Transaction ---');
    console.log(`From: ${tx.from}`);
    console.log(`To: ${tx.to}`);
    console.log(`Value: ${tx.value}`);
    console.log(`Data: ${tx.data}`);

    // Get signer from target network
    let signer;
    if (process.env.DEPLOYER_PRIVATE_KEY) {
        signer = new ethers.Wallet(process.env.DEPLOYER_PRIVATE_KEY, ethers.provider);
        console.log(`\n--- Target Network (private key) ---`);
    } else {
        [signer] = await ethers.getSigners();
        console.log(`\n--- Target Network (mnemonic) ---`);
    }
    console.log(`Sender: ${signer.address}`);

    // Replay the transaction
    console.log('\nSending transaction to target network...');
    const replayTx = await signer.sendTransaction({
        to: tx.to,
        data: tx.data,
        value: tx.value,
    });

    console.log(`Tx hash: ${replayTx.hash}`);
    console.log('Waiting for confirmation...');

    const receipt = await replayTx.wait();
    console.log(`\n✓ Transaction confirmed in block ${receipt?.blockNumber}`);
    console.log('='.repeat(60));
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
