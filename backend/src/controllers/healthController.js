import { isStarting } from '../middleware/startupGate.js';
import { env } from '../config/env.js';
import { sendSuccess } from '../utils/response.js';
import { repository } from '../store/repository.js';
import { sessionStore } from '../services/auth/sessionStore.js';
import { blockchainService } from '../services/blockchainService.js';

export const PROVIDER_URLS = {
  urlhaus: 'https://urlhaus-api.abuse.ch/',
  crtsh: 'https://crt.sh/?q=example.com&output=json&exclude=expired&deduplicate=Y',
  googleSafeBrowsing: 'https://safebrowsing.googleapis.com/',
  certspotter: 'https://api.certspotter.com/v1/issuances?domain=example.com',
};

const CACHE_TTL_MS = 30 * 1000; // 30 seconds
let cachedHealth = null;
let cacheExpiresAt = 0;

/**
 * Reset health cache (primarily for tests)
 */
export function _clearHealthCache() {
  cachedHealth = null;
  cacheExpiresAt = 0;
}

/**
 * Lightweight reachability check with a 3-second timeout (AbortController).
 * Any HTTP response means "reachable" = "ok".
 * A timeout, DNS failure, or network error = "unavailable".
 */
export async function checkReachability(url, timeoutMs = 3000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'CyberLens-Scanner/1.0',
        Accept: 'application/json, text/plain, */*',
      },
      signal: controller.signal,
    });
    if (res.status >= 500) {
      return 'unavailable';
    }
    return 'ok';
  } catch {
    return 'unavailable';
  } finally {
    clearTimeout(timer);
  }
}

/**
 * GET /api/health
 */
export async function getHealth(req, res, next) {
  try {
    res.setHeader('Cache-Control', 'no-store');

    const now = Date.now();
    if (cachedHealth && now < cacheExpiresAt) {
      return sendSuccess(res, cachedHealth);
    }

    // 1. Database: a real round-trip for Supabase; memory is always reachable
    const database = (await repository.ping().catch(() => false)) ? 'ok' : 'unavailable';

    // 2. AI: unavailable when GEMINI_API_KEY is empty, otherwise ok
    const ai = env.GEMINI_API_KEY ? 'ok' : 'unavailable';

    // 3. Blockchain: "ok" only when the configured RPC answers AND the registry
    //    contract has code at the configured address (real check, 3 s timeout).
    const blockchainCheck = blockchainService.isConfigured()
      ? blockchainService.ping({ timeoutMs: 3000 }).then((ok) => (ok ? 'ok' : 'unavailable'), () => 'unavailable')
      : Promise.resolve('unavailable');

    // 4. Provider reachability checks executed in parallel via Promise.allSettled
    const gsbCheck = env.GOOGLE_SAFE_BROWSING_API_KEY
      ? checkReachability(PROVIDER_URLS.googleSafeBrowsing, 3000)
      : Promise.resolve('unavailable');

    const urlhausCheck = checkReachability(PROVIDER_URLS.urlhaus, 3000);
    const crtshCheck = checkReachability(PROVIDER_URLS.crtsh, 3000);
    // Cert Spotter is the certificate-log fallback used by the CT check when crt.sh is down.
    const certspotterCheck = checkReachability(PROVIDER_URLS.certspotter, 3000);

    const [gsbResult, urlhausResult, crtshResult, chainResult, certspotterResult] = await Promise.allSettled([
      gsbCheck,
      urlhausCheck,
      crtshCheck,
      blockchainCheck,
      certspotterCheck,
    ]);
    const blockchain = chainResult.status === 'fulfilled' ? chainResult.value : 'unavailable';

    const googleSafeBrowsing = gsbResult.status === 'fulfilled' ? gsbResult.value : 'unavailable';
    const urlhaus = urlhausResult.status === 'fulfilled' ? urlhausResult.value : 'unavailable';
    const crtsh = crtshResult.status === 'fulfilled' ? crtshResult.value : 'unavailable';
    const certspotter = certspotterResult.status === 'fulfilled' ? certspotterResult.value : 'unavailable';
    // Certificate logs are covered when either provider answers.
    const certificateLogs = crtsh === 'ok' || certspotter === 'ok' ? 'ok' : 'unavailable';

    // 5. Overall status: "degraded" if the database, urlhaus, Google Safe Browsing, or BOTH
    //    certificate-log providers (crt.sh and its Cert Spotter fallback) are unavailable.
    const isDegraded =
      database === 'unavailable' ||
      urlhaus === 'unavailable' ||
      certificateLogs === 'unavailable' ||
      googleSafeBrowsing === 'unavailable';

    const healthPayload = {
      status: isDegraded ? 'degraded' : 'ok',
      databaseProvider: repository.kind || 'memory',
      services: {
        database,
        googleSafeBrowsing,
        urlhaus,
        crtsh,
        certspotter,
        certificateLogs,
        ai,
        blockchain,
      },
    };

    cachedHealth = healthPayload;
    cacheExpiresAt = now + CACHE_TTL_MS;

    return sendSuccess(res, healthPayload);
  } catch (err) {
    next(err);
  }
}

/** Probe the repository without side effects. */
async function repositoryOk() {
  try {
    await repository.getInvestigation('__health_probe__');
    return true;
  } catch {
    return false;
  }
}

/**
 * GET /api/health/live — the process is up and responding.
 * Never checks dependencies (a provider outage must not restart the server).
 */
export function getLiveness(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  return sendSuccess(res, { status: 'alive', timestamp: new Date().toISOString(), uptime: Math.round(process.uptime()) });
}

/**
 * GET /api/health/ready — 200 only when the API can serve requests:
 * repository reachable, session store working, essential config present.
 * External providers are NOT required (investigations degrade gracefully).
 */
export async function getReadiness(req, res, next) {
  try {
    res.setHeader('Cache-Control', 'no-store');
    const [repo, session] = await Promise.all([
      repositoryOk(),
      sessionStore.probe().catch(() => false),
    ]);
    const configOk = Boolean(env.SESSION_SECRET && env.SESSION_SECRET.length >= 32 && env.FRONTEND_ORIGINS?.length);
    const checks = {
      startup: isStarting() ? 'unavailable' : 'ok',
      repository: repo ? 'ok' : 'unavailable',
      session: session ? 'ok' : 'unavailable',
      config: configOk ? 'ok' : 'unavailable',
    };
    const ready = Object.values(checks).every((v) => v === 'ok');
    const body = { status: ready ? 'ready' : 'not_ready', timestamp: new Date().toISOString(), checks };
    if (ready) return sendSuccess(res, body);
    return res.status(503).json({
      success: false,
      ...body,
      error: { code: 'NOT_READY', message: 'The API is not ready to serve requests.', details: {} },
    });
  } catch (err) {
    next(err);
  }
}
