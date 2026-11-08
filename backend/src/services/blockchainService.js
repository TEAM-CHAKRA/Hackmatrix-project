import { ethers } from 'ethers';
import { env } from '../config/env.js';
import { logger } from '../utils/logger.js';

/**
 * Bridge to the CyberlensRegistry contract (contracts/contracts/CyberlensRegistry.sol).
 *
 * CHAIN_MODE=local   → LOCAL_RPC_URL (Hardhat node), explorerUrl = null
 * CHAIN_MODE=sepolia → SEPOLIA_RPC_URL, explorer links to sepolia.etherscan.io
 *
 * Nothing here ever fakes a result: "registered" is returned only with a mined
 * receipt; any RPC problem surfaces as an error the controller reports as
 * CHAIN_UNAVAILABLE.
 */

export const REGISTRY_ABI = [
  'function registerReport(string reportId, bytes32 reportHash) returns (uint256)',
  'function reviseReport(string reportId, bytes32 newHash) returns (uint256)',
  'function getRecord(string reportId) view returns (tuple(bytes32 reportHash, uint256 timestamp, uint256 blockNumber, uint256 revision, uint8 status, address reporter))',
  'function getRecordByHash(bytes32 reportHash) view returns (string reportId, tuple(bytes32 reportHash, uint256 timestamp, uint256 blockNumber, uint256 revision, uint8 status, address reporter) rec, uint256 hashRevision)',
  'function registrars(address) view returns (bool)',
  'event ReportRegistered(string reportId, bytes32 indexed reportHash, uint256 revision, address indexed reporter)',
  'error NotOwner()',
  'error NotRegistrar()',
  'error InvalidHash()',
  'error InvalidId()',
  'error NotFound()',
  'error HashAlreadyUsed()',
  'error HashMismatchUseRevise()',
  'error SameHash()',
];

const STATUS_NAMES = ['registered', 'validated', 'disputed'];

export class ChainError extends Error {
  constructor(message, { kind = 'unavailable', txHash, reason } = {}) {
    super(message);
    this.name = 'ChainError';
    this.kind = kind; // unavailable | rejected | timeout | config
    this.txHash = txHash;
    this.reason = reason;
  }
}

const toBytes32 = (hex) => `0x${String(hex).replace(/^0x/i, '').toLowerCase()}`;
const fromBytes32 = (b) => String(b).replace(/^0x/i, '').toLowerCase();

function withTimeout(promise, ms, label) {
  let t;
  return Promise.race([
    promise.finally(() => clearTimeout(t)),
    new Promise((_, reject) => {
      t = setTimeout(() => reject(new ChainError(`${label} timed out`, { kind: 'timeout' })), ms);
      t.unref?.();
    }),
  ]);
}

function settings() {
  const local = env.CHAIN_MODE !== 'sepolia';
  return {
    local,
    network: local ? 'Hardhat Local' : 'Sepolia',
    rpcUrl: local ? env.LOCAL_RPC_URL : env.SEPOLIA_RPC_URL,
    address: env.REGISTRY_CONTRACT_ADDRESS,
    key: env.REGISTRY_SIGNER_PRIVATE_KEY,
    explorer: local ? null : 'https://sepolia.etherscan.io/tx/',
  };
}

let cache = null; // { fingerprint, provider, contract, wallet }
let writeQueue = Promise.resolve(); // serialise writes so nonces never collide

function connection({ needSigner = false } = {}) {
  const s = settings();
  if (!s.rpcUrl || !ethers.isAddress(s.address)) throw new ChainError('Blockchain is not configured on this server.', { kind: 'config' });
  if (needSigner && !s.key) throw new ChainError('No registry signer key is configured on this server.', { kind: 'config' });
  const fingerprint = `${s.rpcUrl}|${s.address}|${s.key ? 'k' : ''}`;
  if (!cache || cache.fingerprint !== fingerprint) {
    // Static network: skip auto-detection (which retries and logs forever when the RPC is down).
    const network = ethers.Network.from(s.local ? 31337 : 11155111);
    const provider = new ethers.JsonRpcProvider(s.rpcUrl, network, { staticNetwork: network });
    const wallet = s.key ? new ethers.NonceManager(new ethers.Wallet(s.key, provider)) : null;
    const contract = new ethers.Contract(s.address, REGISTRY_ABI, wallet || provider);
    cache = { fingerprint, provider, wallet, contract };
  }
  return { ...cache, s };
}

function explorerUrl(txHash) {
  const s = settings();
  return s.explorer && txHash ? `${s.explorer}${txHash}` : null;
}

function decodeRevert(err) {
  const name = err?.revert?.name || err?.info?.error?.data?.name;
  if (name) return name;
  const data = err?.data || err?.info?.error?.data;
  if (typeof data === 'string' && data.startsWith('0x')) {
    try {
      return new ethers.Interface(REGISTRY_ABI).parseError(data)?.name;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function wrap(err, label) {
  if (err instanceof ChainError) return err;
  const reason = decodeRevert(err);
  if (reason) return new ChainError(`${label} was rejected by the contract (${reason}).`, { kind: 'rejected', reason });
  logger.warn('chain_error', { label, code: err?.code, message: err?.shortMessage || err?.message });
  return new ChainError(`${label} failed: the blockchain network could not be reached.`, { kind: 'unavailable' });
}

function shapeRecord(rec) {
  if (!rec || rec.timestamp === 0n) return null;
  return {
    reportHash: fromBytes32(rec.reportHash),
    timestamp: new Date(Number(rec.timestamp) * 1000).toISOString(),
    blockNumber: Number(rec.blockNumber),
    revision: Number(rec.revision),
    status: STATUS_NAMES[Number(rec.status)] || 'registered',
    reporter: rec.reporter,
  };
}

export const blockchainService = {
  /** Safe description for logs/UI (no RPC URL, no key). */
  describe() {
    const s = settings();
    return {
      configured: Boolean(s.rpcUrl && ethers.isAddress(s.address)),
      canWrite: Boolean(s.rpcUrl && ethers.isAddress(s.address) && s.key),
      network: s.network,
      contractAddress: ethers.isAddress(s.address) ? s.address : null,
    };
  },

  isConfigured() {
    return this.describe().configured;
  },

  /** True when the RPC answers and contract code exists at the address. */
  async ping({ timeoutMs = 3000 } = {}) {
    try {
      const { provider, s } = connection();
      const code = await withTimeout(provider.getCode(s.address), timeoutMs, 'Chain ping');
      return Boolean(code && code !== '0x');
    } catch {
      return false;
    }
  },

  /** Current on-chain record for an ID, or null. */
  async getRecord(reportId) {
    try {
      const { contract } = connection();
      return shapeRecord(await withTimeout(contract.getRecord(String(reportId).toUpperCase()), 15000, 'Chain lookup'));
    } catch (err) {
      throw wrap(err, 'Chain lookup');
    }
  },

  /** → { reportId, record, hashRevision } or null when the hash is unknown. */
  async getRecordByHash(reportHash) {
    try {
      const { contract } = connection();
      const [reportId, rec, hashRevision] = await withTimeout(contract.getRecordByHash(toBytes32(reportHash)), 15000, 'Chain lookup');
      if (!reportId) return null;
      return { reportId, record: shapeRecord(rec), hashRevision: Number(hashRevision) };
    } catch (err) {
      throw wrap(err, 'Chain lookup');
    }
  },

  /** Find the transaction that first registered a hash (via the indexed event). */
  async findRegistrationTx(reportHash) {
    try {
      const { contract } = connection();
      const logs = await withTimeout(contract.queryFilter(contract.filters.ReportRegistered(null, toBytes32(reportHash))), 15000, 'Event lookup');
      const log = logs[0];
      return log ? { txHash: log.transactionHash, blockNumber: log.blockNumber } : null;
    } catch {
      return null;
    }
  },

  /** Status of a previously sent transaction: 'confirmed' | 'failed' | 'pending'. */
  async getTxStatus(txHash) {
    try {
      const { provider } = connection();
      const receipt = await withTimeout(provider.getTransactionReceipt(txHash), 15000, 'Receipt lookup');
      if (!receipt) return { status: 'pending' };
      return { status: receipt.status === 1 ? 'confirmed' : 'failed', blockNumber: receipt.blockNumber };
    } catch (err) {
      throw wrap(err, 'Receipt lookup');
    }
  },

  /**
   * Register (id, hash) and wait for 1 mined block.
   * → { status:'registered', txHash, blockNumber, timestamp, revision, network, contractAddress, explorerUrl }
   * Throws ChainError(kind 'timeout', txHash) if mining takes longer than CHAIN_TX_TIMEOUT_MS.
   */
  async register(reportId, reportHash) {
    const id = String(reportId).toUpperCase();
    const run = async () => {
      const { contract, s } = connection({ needSigner: true });
      let tx;
      try {
        tx = await withTimeout(contract.registerReport(id, toBytes32(reportHash)), 30000, 'Sending the transaction');
      } catch (err) {
        throw wrap(err, 'Registration');
      }
      let receipt;
      try {
        receipt = await withTimeout(tx.wait(1), env.CHAIN_TX_TIMEOUT_MS, 'Waiting for the block');
      } catch (err) {
        if (err instanceof ChainError && err.kind === 'timeout') {
          throw new ChainError('The transaction was sent but is not mined yet.', { kind: 'timeout', txHash: tx.hash });
        }
        throw wrap(err, 'Registration');
      }
      if (!receipt || receipt.status !== 1) throw new ChainError('The registration transaction failed on-chain.', { kind: 'rejected', txHash: tx.hash });
      const rec = await this.getRecord(id);
      if (!rec || rec.reportHash !== fromBytes32(reportHash)) {
        throw new ChainError('The transaction was mined but the on-chain record does not match.', { kind: 'rejected', txHash: tx.hash });
      }
      return {
        status: 'registered',
        txHash: tx.hash,
        blockNumber: receipt.blockNumber,
        timestamp: rec.timestamp,
        revision: rec.revision,
        network: s.network,
        contractAddress: s.address,
        explorerUrl: explorerUrl(tx.hash),
      };
    };
    const result = writeQueue.then(run, run);
    writeQueue = result.catch(() => {});
    return result;
  },

  explorerUrl,

  /** Test hook: forget the cached connection (after changing env). */
  _reset() {
    cache = null;
    writeQueue = Promise.resolve();
  },
};
