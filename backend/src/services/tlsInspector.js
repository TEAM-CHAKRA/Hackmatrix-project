import tls from 'node:tls';
import net from 'node:net';
import fs from 'node:fs';
import crypto from 'node:crypto';

const distrustedCAsPath = new URL('../data/distrustedCAs.json', import.meta.url);
const DISTRUSTED_CAS = JSON.parse(fs.readFileSync(distrustedCAsPath, 'utf-8'));

/**
 * Check if a certificate or its chain matches any known distrusted CA
 * 
 * @param {string|Array<string>} issuerInput Certificate issuer string, or list of issuers
 * @param {object} [options]
 * @param {string} [options.validFrom] Leaf certificate's validFrom ISO string
 * @param {Array<object|string>} [options.chain] Certificate chain
 * @returns {{
 *   status: 'match_found' | 'no_match' | 'not_checked',
 *   source: string,
 *   note: string,
 *   entry?: object
 * }}
 */
export function checkDistrustedCA(issuerInput = '', options = {}) {
  const opts = typeof options === 'string' ? { validFrom: options } : (options || {});
  const { validFrom = null, chain = [] } = opts;

  if (!issuerInput && (!chain || chain.length === 0)) {
    return { status: 'not_checked', source: 'Distrusted CA catalog', note: 'No certificate issuer available' };
  }

  // Collect all issuer strings and non-leaf subject strings
  // RULE: match patterns ONLY against issuer DNs and non-leaf subject DNs, NEVER the leaf's subject
  const stringsToCheck = [];
  if (typeof issuerInput === 'string' && issuerInput) {
    stringsToCheck.push(issuerInput);
  } else if (Array.isArray(issuerInput)) {
    stringsToCheck.push(...issuerInput.filter(Boolean));
  } else if (issuerInput && typeof issuerInput === 'object') {
    if (typeof issuerInput.issuer === 'string') {
      stringsToCheck.push(issuerInput.issuer);
    } else if (issuerInput.issuer && typeof issuerInput.issuer === 'object') {
      stringsToCheck.push(Object.entries(issuerInput.issuer).map(([k, v]) => `${k}=${v}`).join(', '));
    } else {
      stringsToCheck.push(Object.entries(issuerInput).map(([k, v]) => `${k}=${v}`).join(', '));
    }
  }

  for (const item of chain) {
    if (typeof item === 'string') {
      stringsToCheck.push(item);
    } else if (item && typeof item === 'object') {
      // Check issuer DN
      if (typeof item.issuer === 'string') {
        stringsToCheck.push(item.issuer);
      } else if (item.issuer && typeof item.issuer === 'object') {
        stringsToCheck.push(Object.entries(item.issuer).map(([k, v]) => `${k}=${v}`).join(', '));
      }

      // Check subject DN ONLY for non-leaf certificates (intermediate or root)
      const isLeaf = item.role === 'leaf' || item.isLeaf === true;
      if (!isLeaf) {
        if (typeof item.subject === 'string') {
          stringsToCheck.push(item.subject);
        } else if (item.subject && typeof item.subject === 'object') {
          stringsToCheck.push(Object.entries(item.subject).map(([k, v]) => `${k}=${v}`).join(', '));
        }
      }
    }
  }

  for (const entry of DISTRUSTED_CAS) {
    const hasPatternMatch = entry.patterns.some((pattern) =>
      stringsToCheck.some((str) => str.toLowerCase().includes(pattern.toLowerCase()))
    );

    if (!hasPatternMatch) {
      continue;
    }

    // Pattern matched; now evaluate date condition and root condition
    const needsDate = Boolean(entry.notBeforeAfter || entry.notBeforeBefore);
    if (needsDate) {
      if (!validFrom) {
        return {
          status: 'not_checked',
          source: 'Distrusted CA catalog',
          note: `Certificate authority matches ${entry.name}, but validFrom date is unavailable to check distrust condition.`,
          entry,
        };
      }

      const certTime = new Date(validFrom).getTime();
      if (isNaN(certTime)) {
        return {
          status: 'not_checked',
          source: 'Distrusted CA catalog',
          note: `Certificate authority matches ${entry.name}, but validFrom date is invalid to check distrust condition.`,
          entry,
        };
      }

      if (entry.notBeforeAfter) {
        const afterTime = new Date(entry.notBeforeAfter).getTime();
        if (certTime < afterTime) {
          // Issued before distrust effective date; not flagged
          continue;
        }
      }

      if (entry.notBeforeBefore) {
        const beforeTime = new Date(entry.notBeforeBefore).getTime();
        if (certTime >= beforeTime) {
          // Issued on or after distrust cutoff; not flagged
          continue;
        }
      }
    }

    if (entry.requireNoDigiCertRoot) {
      const hasDigiCert = chain.some((c) => {
        const issuer = typeof c === 'string' ? c : (c.issuer?.CN || c.issuer || '');
        const subject = typeof c === 'string' ? c : (c.subject?.CN || c.subject || '');
        return `${issuer} ${subject}`.toLowerCase().includes('digicert');
      }) || stringsToCheck.some((s) => s.toLowerCase().includes('digicert'));

      if (hasDigiCert) {
        // Chained to DigiCert root, so legacy distrust rule does not apply
        continue;
      }
    }

    return {
      status: 'match_found',
      source: 'Distrusted CA catalog',
      note: `Certificate issued by distrusted authority (${entry.name}): ${entry.reason} (Deprecation cited: ${entry.sourceUrl})`,
      entry,
    };
  }

  return {
    status: 'no_match',
    source: 'Distrusted CA catalog',
    note: 'Certificate issuer is not in known distrusted list.',
  };
}

/**
 * Inspect TLS certificate and crypto attributes on validatedIp:443
 * 
 * @param {object} params
 * @param {string} params.hostname
 * @param {string} params.validatedIp
 * @param {boolean} [params.isHttps] Whether the requested target used HTTPS
 * @param {number} [params.timeoutMs=5000]
 * @returns {Promise<{
 *   id: 'tls',
 *   name: 'TLS inspection',
 *   source: 'TLS inspection',
 *   status: 'completed' | 'unavailable' | 'error',
 *   detail?: string,
 *   tls: object,
 *   findings: Array<object>
 * }>}
 */
export async function inspectTls({
  hostname,
  validatedIp,
  isHttps = true,
  timeoutMs = 5000,
  tlsConnectFn = tls.connect,
}) {
  const findings = [];

  return new Promise((resolve) => {
    let resolved = false;

    // Connect raw TLS socket to validated IP directly
    const socketOptions = {
      host: validatedIp,
      port: 443,
      // RFC 6066: literal IPv4 and IPv6 addresses are not permitted in "HostName" SNI
      servername: net.isIP(hostname) ? undefined : hostname,
      timeout: timeoutMs,
      rejectUnauthorized: false, // gather cert information even if untrusted
    };

    const socket = tlsConnectFn(socketOptions, () => {
      if (resolved) return;
      resolved = true;

      try {
        const cert = socket.getPeerCertificate(true); // detailed cert with full chain
        const authorized = socket.authorized;
        const authError = socket.authorizationError;

        if (!cert || Object.keys(cert).length === 0) {
          socket.destroy();
          return resolve({
            id: 'tls',
            name: 'TLS inspection',
            source: 'TLS inspection',
            status: 'completed',
            detail: 'No peer certificate presented',
            tls: {
              status: 'unavailable',
              httpsAvailable: false,
              note: 'Server did not present a peer certificate.',
            },
            findings: [],
          });
        }

        const validFrom = cert.valid_from ? new Date(cert.valid_from).toISOString() : null;
        const validTo = cert.valid_to ? new Date(cert.valid_to).toISOString() : null;
        const nowMs = Date.now();
        const validToMs = validTo ? new Date(validTo).getTime() : 0;
        const daysRemaining = validToMs ? Math.floor((validToMs - nowMs) / (1000 * 60 * 60 * 24)) : 0;
        const isExpired = daysRemaining < 0;

        // SAN and Hostname matching
        const sanList = cert.subjectaltname
          ? cert.subjectaltname.split(',').map((s) => s.trim().replace(/^DNS:/i, ''))
          : [];
        const subjectCN = cert.subject?.CN || '';
        const allNames = [subjectCN, ...sanList].filter(Boolean);

        const hostnameMatch = net.isIP(hostname)
          ? true
          : allNames.some((name) => {
            if (name === hostname) return true;
            if (name.startsWith('*.')) {
              const wildDomain = name.slice(2);
              return hostname.endsWith(wildDomain) && hostname.split('.').length === name.split('.').length;
            }
            return false;
          });

        // Key and Cryptographic strength check
        const bits = cert.bits || 0;

        // Extract signature algorithm reliably via X509Certificate or fallback
        let x509 = null;
        if (typeof socket.getPeerX509Certificate === 'function') {
          try {
            x509 = socket.getPeerX509Certificate();
          } catch {}
        }
        if (!x509 && cert.raw) {
          try {
            x509 = new crypto.X509Certificate(cert.raw);
          } catch {}
        }

        let sigAlg = x509?.signatureAlgorithm || null;
        if (!sigAlg) {
          if (typeof cert.sigalg === 'string' && cert.sigalg.trim().length > 0) {
            sigAlg = cert.sigalg.trim();
          } else if (typeof cert.signatureAlgorithm === 'string' && cert.signatureAlgorithm.trim().length > 0) {
            sigAlg = cert.signatureAlgorithm.trim();
          }
        }
        if (!sigAlg || (typeof sigAlg === 'string' && sigAlg.trim() === '')) {
          sigAlg = null;
        }

        let keyType = (cert.asn1Curve || (sigAlg && /ecdsa/i.test(sigAlg))) ? 'EC' : 'RSA';

        const isWeakKey = (keyType === 'RSA' && bits > 0 && bits < 2048) || (keyType === 'EC' && bits > 0 && bits < 256);
        const isWeakSig = sigAlg ? /md5|sha1/i.test(sigAlg) : false;
        const hasWeakCrypto = isWeakKey || isWeakSig;

        // Build chain representation
        const chain = [];
        let curr = cert;
        let depth = 0;
        while (curr && depth < 5) {
          chain.push({
            role: depth === 0 ? 'leaf' : curr.issuer?.CN === curr.subject?.CN ? 'root' : 'intermediate',
            subject: curr.subject?.CN || (curr.subject ? Object.values(curr.subject).join(' ') : ''),
            issuer: curr.issuer?.CN || (curr.issuer ? Object.values(curr.issuer).join(' ') : ''),
            validFrom: curr.valid_from ? new Date(curr.valid_from).toISOString() : null,
            validTo: curr.valid_to ? new Date(curr.valid_to).toISOString() : null,
          });
          if (!curr.issuerCertificate || curr.issuerCertificate === curr) break;
          curr = curr.issuerCertificate;
          depth++;
        }

        // Distrusted CA check (requires pattern match on chain cert AND date condition using leaf validFrom)
        const issuerStr = cert.issuer ? Object.entries(cert.issuer).map(([k, v]) => `${k}=${v}`).join(', ') : '';
        const distrustResult = checkDistrustedCA(issuerStr, { validFrom, chain });

        // Derive overall TLS status
        let tlsStatus = 'valid';

        if (distrustResult.status === 'match_found') {
          tlsStatus = 'untrusted_chain';
          findings.push({
            id: 'f_tls_distrusted_ca',
            title: 'Certificate issued by distrusted authority',
            description: distrustResult.note,
            severity: 'high',
            category: 'heuristic',
            source: 'TLS inspection',
            checkId: 'tls',
            evidence: { Issuer: issuerStr, 'Distrusted CA': distrustResult.entry?.name || 'Unknown' },
          });
        }

        if (isExpired) {
          if (tlsStatus === 'valid') tlsStatus = 'expired';
          findings.push({
            id: 'f_tls_expired',
            title: 'TLS certificate expired',
            description: `The certificate expired on ${validTo}. Browsers will warn users that the connection is insecure.`,
            severity: 'high',
            category: 'weakness',
            source: 'TLS inspection',
            checkId: 'tls',
            evidence: { 'Valid to': validTo, 'Days expired': String(Math.abs(daysRemaining)) },
          });
        }

        if (!hostnameMatch) {
          if (tlsStatus === 'valid') tlsStatus = 'hostname_mismatch';
          findings.push({
            id: 'f_tls_mismatch',
            title: 'Certificate hostname mismatch',
            description: `The certificate is issued for "${subjectCN}" (${sanList.slice(0, 3).join(', ')}), which does not match "${hostname}".`,
            severity: 'high',
            category: 'weakness',
            source: 'TLS inspection',
            checkId: 'tls',
            evidence: { 'Target host': hostname, 'Certificate subject': subjectCN, SAN: sanList.join(', ') },
          });
        }

        if (!authorized && distrustResult.status !== 'match_found') {
          if (tlsStatus === 'valid') tlsStatus = 'untrusted_chain';
          findings.push({
            id: 'f_tls_untrusted',
            title: 'Untrusted TLS certificate chain',
            description: `Certificate validation failed: ${authError || 'Self-signed or untrusted root'}.`,
            severity: 'high',
            category: 'weakness',
            source: 'TLS inspection',
            checkId: 'tls',
            evidence: { Error: String(authError || 'Untrusted chain') },
          });
        }

        if (hasWeakCrypto) {
          if (tlsStatus === 'valid') tlsStatus = 'weak_crypto';
          findings.push({
            id: 'f_tls_weak_crypto',
            title: 'Weak cryptographic algorithm or key length',
            description: `The certificate uses weak parameters (Key: ${keyType} ${bits} bits, Signature: ${sigAlg || 'undetermined'}).`,
            severity: 'medium',
            category: 'weakness',
            source: 'TLS inspection',
            checkId: 'tls',
            evidence: {
              'Key type': keyType,
              Bits: String(bits),
              'Signature algorithm': sigAlg ?? 'not_checked',
              'Weak signature check': sigAlg ? (isWeakSig ? 'failed' : 'passed') : 'not_checked',
            },
          });
        }

        if (findings.length === 0) {
          const validEvidence = {
            'Hostname match': 'Yes',
            'Chain trusted': 'Yes',
            Issuer: issuerStr,
          };
          if (sigAlg === null) {
            validEvidence['Signature algorithm'] = 'not_checked';
            validEvidence['Weak signature check'] = 'not_checked';
          } else {
            validEvidence['Signature algorithm'] = sigAlg;
            validEvidence['Weak signature check'] = 'passed';
          }

          findings.push({
            id: 'f_tls_valid',
            title: 'Valid TLS certificate with hostname match',
            description: 'The certificate is within its validity period, matches the hostname, and chains to a trusted root.',
            severity: 'info',
            category: 'informational',
            source: 'TLS inspection',
            checkId: 'tls',
            evidence: validEvidence,
          });
        }

        const tlsData = {
          status: tlsStatus,
          httpsAvailable: true,
          valid: authorized && !isExpired && hostnameMatch && distrustResult.status !== 'match_found',
          validFrom,
          validTo,
          daysRemaining,
          issuer: issuerStr,
          subject: subjectCN,
          san: sanList,
          hostnameMatch,
          publicKey: { type: keyType, bits },
          signatureAlgorithm: sigAlg,
          chainTrusted: authorized,
          chain,
          distrust: distrustResult,
          ct: { status: 'completed' },
          revocation: { status: 'not_checked' },
        };

        socket.destroy();
        return resolve({
          id: 'tls',
          name: 'TLS inspection',
          source: 'TLS inspection',
          status: 'completed',
          tls: tlsData,
          findings,
        });
      } catch (err) {
        socket.destroy();
        return resolve({
          id: 'tls',
          name: 'TLS inspection',
          source: 'TLS inspection',
          status: 'error',
          detail: `TLS inspection error: ${err.message}`,
          tls: { status: 'unavailable', httpsAvailable: false },
          findings: [],
        });
      }
    });

    socket.on('timeout', () => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      return resolve({
        id: 'tls',
        name: 'TLS inspection',
        source: 'TLS inspection',
        status: isHttps ? 'unavailable' : 'completed',
        detail: 'TLS handshake timed out after 5s',
        tls: { status: isHttps ? 'unavailable' : 'no_https', httpsAvailable: false },
        findings: !isHttps ? [{
          id: 'f_tls_no_https',
          title: 'No HTTPS support',
          description: 'The target does not support HTTPS. Plaintext HTTP exposes traffic to interception.',
          severity: 'medium',
          category: 'weakness',
          source: 'TLS inspection',
          checkId: 'tls',
          evidence: { Reason: 'TLS connection timed out' },
        }] : [],
      });
    });

    socket.on('error', (err) => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      return resolve({
        id: 'tls',
        name: 'TLS inspection',
        source: 'TLS inspection',
        status: isHttps ? 'unavailable' : 'completed',
        detail: `TLS connection failed: ${err.message}`,
        tls: { status: isHttps ? 'unavailable' : 'no_https', httpsAvailable: false },
        findings: !isHttps ? [{
          id: 'f_tls_no_https',
          title: 'No HTTPS support',
          description: 'The target does not support HTTPS. Plaintext HTTP exposes traffic to interception.',
          severity: 'medium',
          category: 'weakness',
          source: 'TLS inspection',
          checkId: 'tls',
          evidence: { Reason: `TLS connection failed: ${err.message}` },
        }] : [],
      });
    });
  });
}
