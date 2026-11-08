/**
 * Deploys CyberlensRegistry and prints the backend .env lines to use.
 *
 *   npm run deploy:local     (needs `npm run node` running in another terminal)
 *   npm run deploy:sepolia   (needs SEPOLIA_RPC_URL + DEPLOYER_PRIVATE_KEY in contracts/.env;
 *                             use a throwaway wallet funded with Sepolia test ETH)
 *
 * Optional: REGISTRAR_ADDRESS in contracts/.env authorises a separate backend
 * signer (otherwise the deployer is the registrar).
 */
const fs = require('fs');
const path = require('path');
const hre = require('hardhat');

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const network = hre.network.name;
  console.log(`Deploying CyberlensRegistry to "${network}" from ${deployer.address} ...`);

  const Registry = await hre.ethers.getContractFactory('CyberlensRegistry');
  const registry = await Registry.deploy();
  await registry.waitForDeployment();
  const address = await registry.getAddress();
  const receipt = await registry.deploymentTransaction().wait(1);

  const registrar = process.env.REGISTRAR_ADDRESS;
  if (registrar && registrar.toLowerCase() !== deployer.address.toLowerCase()) {
    await (await registry.setRegistrar(registrar, true)).wait(1);
    console.log(`Authorised registrar ${registrar}`);
  }

  const out = {
    network,
    chainId: Number((await hre.ethers.provider.getNetwork()).chainId),
    address,
    deployer: deployer.address,
    blockNumber: receipt.blockNumber,
    deployedAt: new Date().toISOString(),
  };
  const dir = path.join(__dirname, '..', 'deployments');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${network}.json`), JSON.stringify(out, null, 2) + '\n');

  console.log(`\nCyberlensRegistry deployed at ${address} (block ${receipt.blockNumber})`);
  console.log('\nAdd these lines to backend/.env:\n');
  console.log(`CHAIN_MODE=${network === 'sepolia' ? 'sepolia' : 'local'}`);
  console.log(`REGISTRY_CONTRACT_ADDRESS=${address}`);
  if (network !== 'sepolia') {
    console.log('LOCAL_RPC_URL=http://127.0.0.1:8545');
    console.log('# REGISTRY_SIGNER_PRIVATE_KEY = the private key of "Account #0" printed by `npm run node`');
  } else {
    console.log('# REGISTRY_SIGNER_PRIVATE_KEY = the registrar wallet key (throwaway Sepolia wallet)');
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
