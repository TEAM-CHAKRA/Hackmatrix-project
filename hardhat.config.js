require('@nomicfoundation/hardhat-ethers');
require('@nomicfoundation/hardhat-chai-matchers');
require('dotenv').config();
const { subtask } = require('hardhat/config');
const { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } = require('hardhat/builtin-tasks/task-names');

const SOLC_VERSION = '0.8.24';

// Use the bundled solc-js compiler (npm package `solc`) instead of downloading
// a native compiler: works offline and behind restrictive networks.
subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args, hre, runSuper) => {
  if (args.solcVersion === SOLC_VERSION) {
    const solc = require('solc');
    return {
      compilerPath: require.resolve('solc/soljson.js'),
      isSolcJs: true,
      version: SOLC_VERSION,
      longVersion: solc.version(),
    };
  }
  return runSuper();
});

const sepoliaKey = process.env.DEPLOYER_PRIVATE_KEY;

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: SOLC_VERSION,
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    localhost: { url: process.env.LOCAL_RPC_URL || 'http://127.0.0.1:8545' },
    ...(process.env.SEPOLIA_RPC_URL && sepoliaKey
      ? { sepolia: { url: process.env.SEPOLIA_RPC_URL, accounts: [sepoliaKey] } }
      : {}),
  },
};
