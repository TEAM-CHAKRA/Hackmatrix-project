const TARGET_BRANDS = [
  'paypal',
  'google',
  'apple',
  'microsoft',
  'amazon',
  'netflix',
  'facebook',
  'instagram',
  'whatsapp',
  'twitter',
  'chase',
  'wellsfargo',
  'bankofamerica',
  'citibank',
  'sbi',
  'hdfc',
  'icici',
];

const HOMOGLYPH_REGEX = /[\u0430\u0441\u0435\u043E\u0440\u0445\u0443\u0456\u0458\u0455]/i;
const VALID_HOSTNAME_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

let ianaBootstrapCache = {
  data: null,
  expiresAt: 0,
};
const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Reset IANA bootstrap cache (for testing)
 */
export function _resetRdapCache() {
  ianaBootstrapCache = { data: null, expiresAt: 0 };
}

/**
 * Fetch and cache IANA RDAP bootstrap data in memory for 24 hours
 */
async function getIanaBootstrap(fetchFn, signal) {
  const now = Date.now();
  if (ianaBootstrapCache.data && now < ianaBootstrapCache.expiresAt) {
    return ianaBootstrapCache.data;
  }
  try {
    const res = await fetchFn('https://data.iana.org/rdap/dns.json', {
      method: 'GET',
      headers: {
        'User-Agent': 'CyberLens-Scanner/1.0',
        Accept: 'application/json, application/rdap+json',
      },
      signal,
    });
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.services)) {
        ianaBootstrapCache = {
          data,
          expiresAt: Date.now() + BOOTSTRAP_TTL_MS,
        };
        return data;
      }
    }
  } catch {
    if (ianaBootstrapCache.data) return ianaBootstrapCache.data;
  }
  return null;
}

function levenshteinDistance(s1, s2) {
  const m = s1.length;
  const n = s2.length;
  const d = Array.from({ length: m + 1 }, () => new Array(n + 1));

  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
    }
  }
  return d[m][n];
}

function normalizeDigitSubstitutions(str) {
  return str
    .replace(/1/g, 'l')
    .replace(/0/g, 'o')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/@/g, 'a')
    .replace(/vv/g, 'w');
}

export const SHARED_HOSTING_SUFFIXES = [
  'appspot.com',
  'github.io',
  'vercel.app',
  'netlify.app',
  'pages.dev',
  'blogspot.com',
  'azurewebsites.net',
  'firebaseapp.com',
  'web.app',
  'glitch.me',
  'herokuapp.com',
  'myshopify.com',
  'workers.dev',
  'fly.dev',
  'surge.sh',
];

export function isSharedHostingDomain(hostname) {
  if (!hostname || typeof hostname !== 'string') return false;
  const clean = hostname.toLowerCase().trim();
  return SHARED_HOSTING_SUFFIXES.some(
    (suffix) => clean === suffix || clean.endsWith(`.${suffix}`)
  );
}

/**
 * Split host into registrable domain and subdomains
 */
export function getDomainParts(hostname) {
  const clean = (hostname || '').toLowerCase().trim();
  const parts = clean.split('.');

  // Check if hostname matches or is under a shared-hosting suffix (PSL private section)
  for (const suffix of SHARED_HOSTING_SUFFIXES) {
    if (clean === suffix) {
      return {
        subdomain: '',
        registrableDomain: clean,
        tokens: parts,
        isSharedHosting: true,
        platformSuffix: suffix,
      };
    }
    if (clean.endsWith(`.${suffix}`)) {
      const suffixParts = suffix.split('.');
      const prefixParts = parts.slice(0, parts.length - suffixParts.length);
      if (prefixParts.length > 0) {
        const tenant = prefixParts[prefixParts.length - 1];
        const registrableDomain = `${tenant}.${suffix}`;
        const subdomain = prefixParts.slice(0, -1).join('.');
        return {
          subdomain,
          registrableDomain,
          tokens: parts,
          isSharedHosting: true,
          platformSuffix: suffix,
        };
      }
    }
  }

  if (parts.length <= 2) {
    return {
      subdomain: '',
      registrableDomain: clean,
      tokens: parts,
      isSharedHosting: false,
    };
  }
  const registrableDomain = parts.slice(-2).join('.');
  const subdomain = parts.slice(0, -2).join('.');
  return {
    subdomain,
    registrableDomain,
    tokens: parts,
    isSharedHosting: false,
  };
}

/**
 * Domain structure, homoglyph, typosquatting, and RDAP analyzer
 * 
 * @param {object} params
 * @param {string} params.hostname
 * @param {Function} [params.fetchFn] Injectable fetch for RDAP testing
 * @returns {Promise<{
 *   id: 'domain',
 *   name: 'Domain and brand analysis',
 *   source: 'Domain analysis',
 *   status: 'completed' | 'error',
 *   findings: Array<object>,
 *   extras: object
 * }>}
 */
export async function analyzeDomain({ hostname, fetchFn = globalThis.fetch }) {
  const findings = [];
  const cleanHost = hostname.toLowerCase().trim();
  const { subdomain, registrableDomain, isSharedHosting } = getDomainParts(cleanHost);

  // 1. Punycode & Homoglyph Detection
  const isPunycode = cleanHost.includes('xn--');
  const hasHomoglyphs = HOMOGLYPH_REGEX.test(cleanHost);

  if (isPunycode || hasHomoglyphs) {
    findings.push({
      id: 'f_domain_homoglyph',
      title: 'Internationalized or homoglyph character detected',
      description: 'The domain uses Punycode (xn--) or look-alike non-ASCII characters that can deceive readers by mimicking familiar Latin letters.',
      severity: 'high',
      category: 'heuristic',
      source: 'Domain analysis',
      checkId: 'domain',
      evidence: {
        Hostname: cleanHost,
        Punycode: isPunycode ? 'Yes' : 'No',
        'Homoglyphs detected': hasHomoglyphs ? 'Yes' : 'No',
      },
    });
  }

  // 2. Typosquatting Detection against target brands
  const domainTokens = cleanHost.split(/[.-]/).filter((t) => t.length >= 3);

  for (const token of domainTokens) {
    const deSubbed = normalizeDigitSubstitutions(token);

    for (const brand of TARGET_BRANDS) {
      if (token === brand) continue; // exact match handled by brand-in-subdomain check if applicable

      const dist = levenshteinDistance(token, brand);
      const subbedDist = levenshteinDistance(deSubbed, brand);

      if (dist === 1 || (subbedDist === 0 && token !== brand)) {
        findings.push({
          id: `f_typo_${brand}`,
          title: 'Brand look-alike in hostname',
          description: `"${token}" closely resembles the brand "${brand}". Character substitution or typosquatting is a common phishing technique.`,
          severity: 'high',
          category: 'heuristic',
          source: 'Domain analysis',
          checkId: 'domain',
          evidence: {
            Token: token,
            Resembles: brand,
            'Edit distance': String(dist),
          },
        });
        break;
      }
    }
  }

  // 3. Brand-in-subdomain Detection
  if (subdomain) {
    for (const brand of TARGET_BRANDS) {
      if (subdomain.includes(brand) && !registrableDomain.includes(brand)) {
        findings.push({
          id: `f_subdomain_${brand}`,
          title: 'Brand name in subdomain',
          description: `The brand name "${brand}" appears in the subdomain of an unrelated domain (${registrableDomain}). Phishers often place trusted brand names in subdomains to trick users.`,
          severity: 'high',
          category: 'heuristic',
          source: 'Domain analysis',
          checkId: 'domain',
          evidence: {
            Brand: brand,
            Subdomain: subdomain,
            'Registrable domain': registrableDomain,
          },
        });
        break;
      }
    }
  }

  // 4. RDAP Lookup (Uses IANA bootstrap file with fallback to rdap.org)
  const extras = {
    subdomain,
    registrableDomain,
    rdap: null,
  };

  if (isSharedHosting) {
    extras.rdap = {
      status: 'not_checked',
      note: 'Shared hosting platform: domain age reflects the platform, not this site',
    };
  } else if (!VALID_HOSTNAME_REGEX.test(registrableDomain)) {
    extras.rdap = {
      status: 'unavailable',
      note: 'Invalid domain name characters for RDAP lookup.',
    };
  } else {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    try {
      // 1. Fetch or get cached IANA bootstrap data
      const bootstrap = await getIanaBootstrap(fetchFn, controller.signal);
      const tld = registrableDomain.split('.').pop().toLowerCase();

      let baseUrl = null;
      if (bootstrap?.services) {
        for (const [tlds, urls] of bootstrap.services) {
          if (Array.isArray(tlds) && tlds.map((t) => t.toLowerCase()).includes(tld)) {
            if (Array.isArray(urls) && urls.length > 0) {
              baseUrl = urls.find((u) => u.startsWith('https://')) || urls[0];
              break;
            }
          }
        }
      }

      let rdapUrl;
      if (baseUrl) {
        const base = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`;
        rdapUrl = `${base}domain/${encodeURIComponent(registrableDomain)}`;
      } else {
        // Fallback to rdap.org
        rdapUrl = `https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`;
      }

      const res = await fetchFn(rdapUrl, {
        method: 'GET',
        headers: {
          Accept: 'application/rdap+json',
          'User-Agent': 'CyberLens-Scanner/1.0',
        },
        signal: controller.signal,
      });

      if (res.ok) {
        const data = await res.json();
        const events = data.events || [];
        const regEvent = events.find((e) => e.eventAction === 'registration');

        let registrationDate = null;
        let ageDays = null;

        if (regEvent && regEvent.eventDate) {
          registrationDate = new Date(regEvent.eventDate).toISOString();
          const diffMs = Date.now() - new Date(regEvent.eventDate).getTime();
          ageDays = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));

          if (ageDays <= 30) {
            findings.push({
              id: 'f_domain_new',
              title: 'Newly registered domain',
              description: `This domain was registered ${ageDays} days ago (${registrationDate.split('T')[0]}). Malicious campaigns frequently utilize newly registered domains.`,
              severity: 'medium',
              category: 'heuristic',
              source: 'Domain analysis',
              checkId: 'domain',
              evidence: {
                'Registered date': registrationDate,
                'Age (days)': String(ageDays),
              },
            });
          }
        }

        extras.rdap = {
          status: 'completed',
          registrationDate,
          ageDays,
          registrar: data.entities?.[0]?.vcardArray?.[1]?.find((v) => v[0] === 'fn')?.[3] || null,
        };
      } else {
        // Treat 403, 404, 429, etc. as unavailable
        extras.rdap = {
          status: 'unavailable',
          note: `RDAP lookup returned HTTP ${res.status}`,
        };
      }
    } catch {
      extras.rdap = {
        status: 'unavailable',
        note: 'RDAP query timed out or was unreachable.',
      };
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    id: 'domain',
    name: 'Domain and brand analysis',
    source: 'Domain analysis',
    status: 'completed',
    findings,
    extras,
  };
}

