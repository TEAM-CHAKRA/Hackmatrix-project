import { z } from 'zod';
import { repository } from '../store/repository.js';
import { sendSuccess, AppError } from '../utils/response.js';
import { ERROR_CODES } from '../config/constants.js';
import { blockchainService, ChainError } from '../services/blockchainService.js';
import {
  buildInvestigationSnapshot,
  buildCommunitySnapshot,
  computeHash,
  CANONICAL_VERSION,
  COMMUNITY_CANONICAL_VERSION,
} from '../services/canonicalHasher.js';
import { logger } from '../utils/logger.js';

/**
 * Phase 8 — On-chain report integrity.
 *
 * Hard rules:
 *  - "registered" only with a real mined receipt; otherwise "pending" or an error.
 *  - Verification recomputes the canonical hash from the stored report and
 *    compares it with the hash READ FROM THE CONTRACT. Nothing is assumed.
 *  - The public feed never contains raw URLs or message text.
 */

const ID_RE = /^(INV|CR)-\d{8}-[0-9A-F]{16}$/i; // IDs are case-insensitive (amendment 21)
const HASH_RE = /^(0x)?[0-9a-fA-F]{64}$/;

export const registerSchema = z
  .object({
    investigationId: z.string().regex(ID_RE, 'Invalid report ID.').optional(),
    communityReportId: z.string().regex(ID_RE, 'Invalid community report ID.').optional(),
  })
  .strict()
  .refine((d) => Boolean(d.investigationId) !== Boolean(d.communityReportId), {
    message: 'Provide exactly one of investigationId or communityReportId.',
  });

export const verifySchema = z
  .object({
    investigationId: z.string().regex(ID_RE, 'Invalid report ID.').optional(),
    reportHash: z.string().regex(HASH_RE, 'reportHash must be 64 hex characters.').optional(),
  })
  .strict()
  .refine((d) => Boolean(d.investigationId) !== Boolean(d.reportHash), {
    message: 'Provide either investigationId or reportHash.',
  });

const chainUnavailable = (message) => new AppError(message, { code: ERROR_CODES.CHAIN_UNAVAILABLE, status: 503 });
const conflict = (message) => new AppError(message, { code: ERROR_CODES.CONFLICT, status: 409 });
const notFound = (message) => new AppError(message, { code: ERROR_CODES.NOT_FOUND, status: 404 });

function toAppError(err) {
  if (err instanceof AppError) return err;
  if (err instanceof ChainError) {
    if (err.kind === 'config')
      return chainUnavailable(`${err.message} Ask the operator to configure CHAIN_MODE and the registry contract.`);
    if (err.kind === 'rejected') return conflict(err.message);
    return chainUnavailable(err.message);
  }
  return err;
}

/** Public registry object (what the report page shows). */
function publicRegistry(entry) {
  if (!entry) return { status: 'not_registered' };
  const out = {
    status: entry.status,
    reportHash: entry.reportHash,
    canonicalVersion: entry.canonicalVersion,
    network: entry.network,
    contractAddress: entry.contractAddress,
    txHash: entry.txHash || null,
    blockNumber: entry.blockNumber ?? null,
    timestamp: entry.timestamp || null,
    explorerUrl: entry.explorerUrl || null,
    revision: entry.revision ?? null,
  };
  if (entry.status === 'failed' && entry.error) out.error = entry.error;
  return out;
}

// Threat-feed metadata derived ONLY from real check results.
function feedMetadata(record) {
  const r = { ...(record.report || {}), ...record };
  const checks = r.checks || [];
  const providerChecks =
    r.type === 'message' ? checks.filter((c) => c.id === 'threat_intel') : checks.filter((c) => c.id === 'gsb' || c.id === 'urlhaus');
  const providers = [];
  for (const c of providerChecks) {
    if (!['completed', 'no_match', 'match_found'].includes(c.status)) continue;
    if (c.id === 'gsb') providers.push('Google Safe Browsing');
    else if (c.id === 'urlhaus') providers.push('URLhaus');
    else if (Array.isArray(c.providers)) providers.push(...c.providers);
  }
  const intelMatches = [];
  for (const f of r.findings || []) {
    if (f.category !== 'confirmed') continue;
    const provider = f.source;
    const threatType = f.evidence?.['Threat type'] || null;
    if (provider) intelMatches.push({ provider, threatType });
  }
  let category = null;
  const types = intelMatches.map((m) => String(m.threatType || '').toUpperCase());
  if (types.some((t) => t.includes('SOCIAL_ENGINEERING') || t.includes('PHISH'))) category = 'phishing';
  else if (types.some((t) => t.includes('MALWARE') || t.includes('UNWANTED') || t.includes('HARMFUL'))) category = 'malware';
  return { providers: [...new Set(providers)], intelMatches, category, classification: r.classification };
}

const inFlight = new Map(); // normalized id -> Promise (one registration at a time per report)

async function registerOnChain({ id, kind, snapshot, onRecord }) {
  const key = id.toUpperCase();
  if (inFlight.has(key)) return inFlight.get(key);

  const work = (async () => {
    const existing = await repository.getRegistryEntryByInvestigationId(key);

    // Idempotency: return the stored mined receipt without a new transaction —
    // unless the chain no longer has it (local chain restarted, or the contract
    // address changed). Then register again so the UI never shows a stale anchor.
    if (existing?.status === 'registered') {
      const current = blockchainService.describe();
      const sameContract = String(existing.contractAddress || '').toLowerCase() === String(current.contractAddress || '').toLowerCase();
      if (sameContract) {
        let rec;
        try {
          rec = await blockchainService.getRecord(key);
        } catch {
          return existing; // chain unreachable: the stored mined receipt still stands
        }
        if (rec && rec.reportHash === existing.reportHash) return existing;
      }
      logger.warn('registry_entry_stale', { id: key, reason: sameContract ? 'record missing on chain' : 'contract changed' });
    }

    // A previous attempt timed out while pending: check its receipt first.
    if (existing?.status === 'pending' && existing.txHash) {
      const tx = await blockchainService.getTxStatus(existing.txHash);
      if (tx.status === 'pending') return existing;
      if (tx.status === 'confirmed') {
        const rec = await blockchainService.getRecord(key);
        if (rec && rec.reportHash === existing.reportHash) {
          const done = await repository.updateRegistryEntry(key, {
            status: 'registered',
            txStatus: 'confirmed',
            blockNumber: tx.blockNumber,
            timestamp: rec.timestamp,
            revision: rec.revision,
            registeredAt: rec.timestamp,
          });
          await onRecord(done);
          return done;
        }
      }
      // failed on-chain → fall through and try again
    }

    if (!blockchainService.describe().canWrite) {
      throw chainUnavailable(
        'Blockchain registration is not configured on this server. Ask the operator to set CHAIN_MODE, REGISTRY_CONTRACT_ADDRESS and the signer key.',
      );
    }

    const { canonicalString, reportHash } = computeHash(snapshot);
    await repository.storeCanonicalSnapshot(key, canonicalString);

    try {
      return await sendOrRecover({ key, kind, snapshot, reportHash, existing, onRecord });
    } catch (err) {
      if (!(err instanceof AppError && err.status === 409)) {
        const message = err instanceof ChainError ? err.message : 'Registration failed.';
        await onRecord({ status: 'failed', error: message });
      }
      throw toAppError(err);
    }
  })();

  inFlight.set(key, work);
  try {
    return await work;
  } finally {
    inFlight.delete(key);
  }
}

/** Send the transaction, or adopt an existing on-chain record (e.g. after a restart). */
async function sendOrRecover({ key, kind, snapshot, reportHash, existing, onRecord }) {
  const base = {
    investigationId: key,
    kind,
    reportHash,
    canonicalVersion: snapshot.canonicalVersion,
    network: blockchainService.describe().network,
    contractAddress: blockchainService.describe().contractAddress,
  };

  // The backend may have restarted after an earlier registration: trust the chain.
  const onChain = await blockchainService.getRecord(key);
  if (onChain) {
    if (onChain.reportHash !== reportHash) {
      throw conflict('This report is already registered on-chain with a different fingerprint. It has changed since registration.');
    }
    const found = await blockchainService.findRegistrationTx(reportHash);
    const entry = {
      ...base,
      status: 'registered',
      txStatus: 'confirmed',
      txHash: found?.txHash || null,
      blockNumber: onChain.blockNumber,
      timestamp: onChain.timestamp,
      registeredAt: onChain.timestamp,
      revision: onChain.revision,
      explorerUrl: blockchainService.explorerUrl(found?.txHash),
    };
    const saved = existing ? await repository.updateRegistryEntry(key, entry) : await repository.createRegistryEntry(entry);
    await onRecord(saved);
    return saved;
  }

  try {
    const result = await blockchainService.register(key, reportHash);
    const entry = { ...base, ...result, txStatus: 'confirmed', registeredAt: result.timestamp };
    const saved = existing ? await repository.updateRegistryEntry(key, entry) : await repository.createRegistryEntry(entry);
    await onRecord(saved);
    logger.info('report_registered', { id: key, txHash: result.txHash, blockNumber: result.blockNumber });
    return saved;
  } catch (err) {
    if (err instanceof ChainError && err.kind === 'timeout' && err.txHash) {
      const pending = {
        ...base,
        status: 'pending',
        txStatus: 'pending',
        txHash: err.txHash,
        explorerUrl: blockchainService.explorerUrl(err.txHash),
      };
      const saved = existing ? await repository.updateRegistryEntry(key, pending) : await repository.createRegistryEntry(pending);
      await onRecord(saved);
      return saved;
    }
    throw err;
  }
}

/** POST /api/registry/register  { investigationId } | { communityReportId } */
export async function registerReport(req, res, next) {
  try {
    const { investigationId, communityReportId } = req.body;

    if (investigationId) {
      const inv = await repository.getInvestigation(investigationId);
      if (!inv) throw notFound(`Investigation '${investigationId}' was not found.`);
      if (inv.status !== 'completed') throw conflict('Only completed reports can be registered. This report is not finished.');

      const meta = feedMetadata(inv);
      const entry = await registerOnChain({
        id: inv.id,
        kind: 'investigation',
        snapshot: buildInvestigationSnapshot(inv),
        onRecord: async (e) => {
          if (e?.investigationId) await repository.updateRegistryEntry(e.investigationId, meta);
          await repository.updateInvestigation(inv.id, { registry: publicRegistry(e) });
        },
      });
      return sendSuccess(res, { registry: publicRegistry(entry) });
    }

    const report = await repository.getCommunityReport(communityReportId);
    if (!report) throw notFound(`Community report '${communityReportId}' was not found.`);
    if (report.status !== 'validated') throw conflict('Only validated community reports can be registered on-chain.');
    const entry = await registerOnChain({
      id: report.id,
      kind: 'community',
      snapshot: buildCommunitySnapshot(report),
      onRecord: async (e) => {
        await repository.updateCommunityReport(report.id, { registry: publicRegistry(e) });
      },
    });
    return sendSuccess(res, { registry: publicRegistry(entry) });
  } catch (err) {
    next(toAppError(err));
  }
}

async function currentHashFor(id) {
  const upper = id.toUpperCase();
  if (upper.startsWith('CR-')) {
    const rep = await repository.getCommunityReport(upper);
    return rep && rep.status === 'validated' ? computeHash(buildCommunitySnapshot(rep)).reportHash : rep ? null : undefined;
  }
  const inv = await repository.getInvestigation(upper);
  if (!inv) return undefined;
  if (inv.status !== 'completed') return null;
  return computeHash(buildInvestigationSnapshot(inv)).reportHash;
}

/** POST /api/registry/verify  { investigationId } | { reportHash } */
export async function verifyReport(req, res, next) {
  try {
    if (!blockchainService.isConfigured()) {
      throw chainUnavailable('On-chain verification is not available: the blockchain is not configured on this server.');
    }
    const { investigationId } = req.body;
    const queriedHash = req.body.reportHash ? req.body.reportHash.toLowerCase().replace(/^0x/, '') : null;

    let id = investigationId ? investigationId.toUpperCase() : null;
    let onChain = null;
    let hashRevision = null;

    if (queriedHash) {
      const byHash = await blockchainService.getRecordByHash(queriedHash);
      if (!byHash) {
        return sendSuccess(res, {
          result: { integrity: 'not_registered', investigationId: null, computedHash: null, onChainHash: null, queriedHash },
        });
      }
      id = byHash.reportId.toUpperCase();
      onChain = byHash.record;
      hashRevision = byHash.hashRevision;
    } else {
      onChain = await blockchainService.getRecord(id);
    }

    const s = blockchainService.describe();
    const entry = await repository.getRegistryEntryByInvestigationId(id);
    const base = {
      investigationId: id,
      canonicalVersion: id.startsWith('CR-') ? COMMUNITY_CANONICAL_VERSION : CANONICAL_VERSION,
      network: s.network,
      contractAddress: s.contractAddress,
      txHash: entry?.txHash || null,
      explorerUrl: entry?.explorerUrl || null,
    };

    if (!onChain) {
      return sendSuccess(res, { result: { ...base, integrity: 'not_registered', computedHash: null, onChainHash: null } });
    }

    const computedHash = await currentHashFor(id);
    if (computedHash === undefined) {
      throw notFound(
        `This server no longer holds report ${id}, so its fingerprint cannot be recomputed. On-chain fingerprint: ${onChain.reportHash}.`,
      );
    }

    const result = {
      ...base,
      integrity: computedHash && computedHash === onChain.reportHash ? 'match' : 'mismatch',
      computedHash,
      onChainHash: onChain.reportHash,
      blockNumber: onChain.blockNumber,
      timestamp: onChain.timestamp,
      revision: onChain.revision,
      onChainStatus: onChain.status,
    };
    if (queriedHash) {
      result.queriedHash = queriedHash;
      if (hashRevision !== null && hashRevision < onChain.revision) {
        result.integrity = 'mismatch';
        result.note = `The hash you entered belongs to revision ${hashRevision}; the report is now at revision ${onChain.revision}.`;
      } else if (queriedHash !== onChain.reportHash) {
        result.integrity = 'mismatch';
      }
    }
    return sendSuccess(res, { result });
  } catch (err) {
    next(toAppError(err));
  }
}

/**
 * GET /api/registry — Threat Feed. Registered investigations only.
 * Never returns raw URLs or message text (IDs, verdicts, provider names only).
 */
export async function listRegistry(req, res, next) {
  try {
    const entries = await repository.listRegistryEntries();
    const items = entries
      .filter((e) => e.kind !== 'community' && (e.status === 'registered' || e.status === 'pending'))
      .sort((a, b) => String(b.registeredAt || '').localeCompare(String(a.registeredAt || '')))
      .map((e) => ({
        investigationId: e.investigationId,
        classification: e.classification || null,
        registeredAt: e.registeredAt || null,
        txStatus: e.status === 'registered' ? 'confirmed' : 'pending',
        txHash: e.txHash || null,
        explorerUrl: e.explorerUrl || null,
        network: e.network,
        revision: e.revision ?? null,
        category: e.category || null,
        providers: e.providers || [],
        intelMatches: e.intelMatches || [],
        validationStatus: null,
      }));
    return sendSuccess(res, { items });
  } catch (err) {
    next(err);
  }
}
