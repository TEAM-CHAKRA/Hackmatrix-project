// ============================================================================
// DEMO FIXTURES — ILLUSTRATIVE DATA ONLY.
// These are NOT results from Google Safe Browsing, URLhaus, crt.sh or any live
// check. Every report built here carries `demo: true`, and the UI shows a
// "Demo fixture" banner. Use them only to develop the UI before the backend
// is connected. Never present them as real threat intelligence.
// ============================================================================

import { SAMPLE_MESSAGES, SAMPLE_URLS } from '../../utils/constants.js';

const DEMO_SOURCE_NOTE = 'Demo fixture (illustrative, not a live result)';

/** Locate phrases in text so highlight offsets always match the original. */
function highlightsFor(text, items) {
  const out = [];
  for (const { phrase, tactic } of items) {
    const start = text.toLowerCase().indexOf(phrase.toLowerCase());
    if (start >= 0) out.push({ start, end: start + phrase.length, phrase: text.slice(start, start + phrase.length), tactic });
  }
  return out.sort((a, b) => a.start - b.start);
}

function baseRegistry() {
  return { status: 'not_registered' };
}

// ---------------------------------------------------------------------------
export function legitUrlFixture(target) {
  return {
    type: 'url',
    target: { display: target, host: 'example.com' },
    classification: 'low_risk',
    confidence: 'high',
    heuristicScore: 6,
    coverage: { completed: 6, total: 6 },
    checks: [
      { id: 'url_analysis', name: 'URL structure analysis', source: 'Internal URL analysis', status: 'completed' },
      { id: 'gsb', name: 'Google Safe Browsing', source: 'Google Safe Browsing', status: 'no_match' },
      { id: 'urlhaus', name: 'URLhaus', source: 'URLhaus', status: 'no_match' },
      { id: 'tls', name: 'TLS inspection', source: 'TLS inspection', status: 'completed' },
      { id: 'ct', name: 'Certificate Transparency', source: 'crt.sh', status: 'completed' },
      { id: 'headers', name: 'HTTP security headers', source: 'HTTP security header inspection', status: 'completed' },
    ],
    findings: [
      {
        id: 'f1',
        title: 'No threat intelligence match',
        description: 'Neither Google Safe Browsing nor URLhaus returned a match for this URL. This means no known threat was detected, not that the site is guaranteed safe.',
        severity: 'info',
        category: 'informational',
        source: 'Google Safe Browsing, URLhaus',
        checkId: 'gsb',
        evidence: { 'Google Safe Browsing': 'No match', URLhaus: 'No match' },
      },
      {
        id: 'f2',
        title: 'Valid TLS certificate with hostname match',
        description: 'The certificate is within its validity period, matches the hostname, and chains to a trusted root.',
        severity: 'info',
        category: 'informational',
        source: 'TLS inspection',
        checkId: 'tls',
        evidence: { 'Hostname match': 'Yes', 'Chain trusted': 'Yes' },
      },
      {
        id: 'f3',
        title: 'Content-Security-Policy header missing',
        description: 'No CSP header was returned. This weakens protection against script injection but is not evidence of phishing.',
        severity: 'low',
        category: 'weakness',
        source: 'HTTP security header inspection',
        checkId: 'headers',
        evidence: { Header: 'Content-Security-Policy', Observed: 'Not present' },
      },
      {
        id: 'f4',
        title: 'HSTS not enabled',
        description: 'Strict-Transport-Security was not returned, so browsers are not told to always use HTTPS for this domain.',
        severity: 'low',
        category: 'weakness',
        source: 'HTTP security header inspection',
        checkId: 'headers',
        evidence: { Header: 'Strict-Transport-Security', Observed: 'Not present' },
      },
    ],
    redirectChain: [{ url: 'https://example.com/', statusCode: 200, suspicious: false }],
    tls: {
      status: 'valid',
      httpsAvailable: true,
      valid: true,
      validFrom: '2026-01-15T00:00:00Z',
      validTo: '2027-01-15T23:59:59Z',
      daysRemaining: 69,
      issuer: 'DigiCert Global G3 TLS ECC SHA384 2020 CA1',
      subject: 'CN=*.example.com',
      san: ['*.example.com', 'example.com'],
      hostnameMatch: true,
      publicKey: { type: 'EC', bits: 256 },
      signatureAlgorithm: 'ecdsa-with-SHA384',
      chainTrusted: true,
      chain: [
        { role: 'leaf', subject: 'CN=*.example.com', issuer: 'DigiCert Global G3 TLS ECC SHA384 2020 CA1', validTo: '2027-01-15T23:59:59Z' },
        { role: 'intermediate', subject: 'DigiCert Global G3 TLS ECC SHA384 2020 CA1', issuer: 'DigiCert Global Root G3', validTo: '2031-04-13T23:59:59Z' },
        { role: 'root', subject: 'DigiCert Global Root G3', issuer: 'DigiCert Global Root G3 (self-signed)', validTo: '2038-01-15T12:00:00Z' },
      ],
      ct: { status: 'completed', entries: 14, note: 'Certificate entries found in public CT logs.' },
      revocation: { status: 'not_checked', note: 'Revocation is not checked in this MVP.' },
    },
    securityHeaders: {
      status: 'completed',
      httpsRedirect: null,
      headers: [
        { name: 'Strict-Transport-Security', present: false, recommendation: 'Enable HSTS with a long max-age.' },
        { name: 'Content-Security-Policy', present: false, recommendation: 'Define a restrictive CSP.' },
        { name: 'X-Frame-Options', present: false, recommendation: 'Set DENY or SAMEORIGIN to prevent clickjacking.' },
        { name: 'X-Content-Type-Options', present: false, recommendation: 'Set nosniff.' },
        { name: 'Referrer-Policy', present: false, recommendation: 'Set strict-origin-when-cross-origin.' },
      ],
      cookies: [],
    },
    explanation: {
      source: 'template',
      summary:
        'CYBERLENS found no known threat for this website. Both threat intelligence sources returned no match, the TLS certificate is valid for this hostname, and the URL structure shows no deceptive patterns. Some recommended security headers are missing, which is a configuration weakness rather than a sign of phishing.',
      keyPoints: [
        'No match in Google Safe Browsing or URLhaus.',
        'Valid certificate that matches the hostname and chains to a trusted root.',
        'Missing HSTS and CSP headers indicate weaker hardening, not malicious intent.',
      ],
    },
    recommendations: [
      'No known threat was detected, but still verify you typed the correct address before signing in.',
      'Only enter personal information if you expected to visit this site.',
    ],
    limitations: [
      'Certificate revocation status was not checked.',
      'Domain registration age and ownership were not queried.',
      'Page content and scripts were not executed or analyzed.',
    ],
    registry: baseRegistry(),
  };
}

// ---------------------------------------------------------------------------
export function suspiciousUrlFixture(target) {
  return {
    type: 'url',
    target: {
      display: 'http://paypa1-account-verify.secure-login.example/signin?session=[redacted]&redirect=confirm',
      host: 'paypa1-account-verify.secure-login.example',
    },
    classification: 'suspicious',
    confidence: 'medium',
    heuristicScore: 58,
    coverage: { completed: 3, total: 6 },
    checks: [
      { id: 'url_analysis', name: 'URL structure analysis', source: 'Internal URL analysis', status: 'completed' },
      { id: 'gsb', name: 'Google Safe Browsing', source: 'Google Safe Browsing', status: 'no_match' },
      { id: 'urlhaus', name: 'URLhaus', source: 'URLhaus', status: 'no_match' },
      { id: 'tls', name: 'TLS inspection', source: 'TLS inspection', status: 'unavailable', detail: 'DNS resolution failed — host does not resolve.' },
      { id: 'ct', name: 'Certificate Transparency', source: 'crt.sh', status: 'error', detail: 'Provider timed out after 8s. Not treated as a clean result.' },
      { id: 'headers', name: 'HTTP security headers', source: 'HTTP security header inspection', status: 'unavailable', detail: 'Host unreachable.' },
    ],
    findings: [
      {
        id: 'f1',
        title: 'Brand look-alike in hostname',
        description: '"paypa1" closely resembles the brand "paypal" (digit 1 substituted for letter l). Typosquatting is a common phishing technique.',
        severity: 'high',
        category: 'heuristic',
        source: 'Internal URL analysis',
        checkId: 'url_analysis',
        evidence: { Token: 'paypa1', 'Resembles': 'paypal', 'Edit distance': '1' },
      },
      {
        id: 'f2',
        title: 'Credential-themed keywords in domain',
        description: 'The hostname combines "account", "verify", "secure" and "login" — wording frequently used to make phishing domains look official.',
        severity: 'medium',
        category: 'heuristic',
        source: 'Internal URL analysis',
        checkId: 'url_analysis',
        evidence: { Keywords: 'account, verify, secure, login' },
      },
      {
        id: 'f3',
        title: 'Unencrypted HTTP on a sign-in path',
        description: 'The URL uses plain HTTP while pointing to a /signin page. Credentials submitted here would not be encrypted in transit.',
        severity: 'medium',
        category: 'heuristic',
        source: 'Internal URL analysis',
        checkId: 'url_analysis',
        evidence: { Scheme: 'http', Path: '/signin' },
      },
      {
        id: 'f4',
        title: 'Session token in query string',
        description: 'A "session" parameter is present in the URL. Its value was redacted before storage and display.',
        severity: 'low',
        category: 'heuristic',
        source: 'Internal URL analysis',
        checkId: 'url_analysis',
        evidence: { Parameter: 'session', Value: '[redacted]' },
      },
      {
        id: 'f5',
        title: 'No threat intelligence match',
        description: 'Neither provider returned a match. Newly created phishing domains often are not yet listed, so this does not reduce the heuristic concerns.',
        severity: 'info',
        category: 'informational',
        source: 'Google Safe Browsing, URLhaus',
        checkId: 'gsb',
        evidence: { 'Google Safe Browsing': 'No match', URLhaus: 'No match' },
      },
    ],
    redirectChain: [
      { url: 'http://paypa1-account-verify.secure-login.example/signin?session=[redacted]&redirect=confirm', statusCode: null, suspicious: true, note: 'Host did not resolve — chain could not be followed.' },
    ],
    tls: { status: 'unavailable', httpsAvailable: false, note: 'TLS inspection could not run because the host does not resolve.' },
    securityHeaders: { status: 'unavailable', note: 'Host unreachable — headers could not be inspected.', headers: [] },
    explanation: {
      source: 'template',
      summary:
        'This URL shows several patterns typical of phishing: the hostname imitates the PayPal brand by swapping a letter for a digit, it stacks credential-related words, and it points to a sign-in page over unencrypted HTTP. No threat intelligence provider has listed it, and the host could not be reached, so TLS and header checks did not run.',
      keyPoints: [
        'Look-alike brand token "paypa1" in the hostname.',
        'Sign-in path served over plain HTTP.',
        'Three of six checks could not complete — conclusions rely on URL heuristics.',
      ],
    },
    recommendations: [
      'Do not enter passwords, OTPs or payment details on this page.',
      'If you need to access your account, type the official website address yourself.',
      'If you received this link in a message, verify the sender through an official channel.',
    ],
    limitations: [
      'TLS certificate inspection was unavailable (host does not resolve).',
      'Certificate Transparency lookup failed (provider timeout).',
      'HTTP security headers could not be inspected.',
    ],
    registry: baseRegistry(),
  };
}

// ---------------------------------------------------------------------------
export function gsbTestFixture(target) {
  return {
    type: 'url',
    target: { display: target, host: 'testsafebrowsing.appspot.com' },
    classification: 'confirmed_malicious',
    confidence: 'high',
    heuristicScore: 95,
    coverage: { completed: 5, total: 6 },
    checks: [
      { id: 'url_analysis', name: 'URL structure analysis', source: 'Internal URL analysis', status: 'completed' },
      { id: 'gsb', name: 'Google Safe Browsing', source: 'Google Safe Browsing', status: 'match_found', detail: 'SOCIAL_ENGINEERING' },
      { id: 'urlhaus', name: 'URLhaus', source: 'URLhaus', status: 'no_match' },
      { id: 'tls', name: 'TLS inspection', source: 'TLS inspection', status: 'completed' },
      { id: 'ct', name: 'Certificate Transparency', source: 'crt.sh', status: 'not_checked', detail: 'Skipped: confirmed match already found.' },
      { id: 'headers', name: 'HTTP security headers', source: 'HTTP security header inspection', status: 'completed' },
    ],
    findings: [
      {
        id: 'f1',
        title: 'Google Safe Browsing: Social engineering',
        description: 'Google Safe Browsing lists this URL under the SOCIAL_ENGINEERING threat type. Note: this is Google\'s official test page, designed to trigger this result safely.',
        severity: 'critical',
        category: 'confirmed',
        source: 'Google Safe Browsing',
        checkId: 'gsb',
        evidence: { 'Threat type': 'SOCIAL_ENGINEERING', 'Platform': 'ANY_PLATFORM', 'Match': 'Exact URL' },
      },
      {
        id: 'f2',
        title: 'Valid TLS certificate',
        description: 'The connection is encrypted with a valid certificate. This protects the connection only and does not offset the confirmed threat match.',
        severity: 'info',
        category: 'informational',
        source: 'TLS inspection',
        checkId: 'tls',
        evidence: { 'Hostname match': 'Yes' },
      },
    ],
    redirectChain: [{ url: 'https://testsafebrowsing.appspot.com/s/phishing.html', statusCode: 200, suspicious: false }],
    tls: {
      status: 'valid',
      httpsAvailable: true,
      valid: true,
      validFrom: '2026-10-06T08:00:00Z',
      validTo: '2026-12-29T08:00:00Z',
      daysRemaining: 52,
      issuer: 'WR2 (Google Trust Services)',
      subject: 'CN=*.appspot.com',
      san: ['*.appspot.com', 'appspot.com'],
      hostnameMatch: true,
      publicKey: { type: 'EC', bits: 256 },
      signatureAlgorithm: 'sha256WithRSAEncryption',
      chainTrusted: true,
      chain: [
        { role: 'leaf', subject: 'CN=*.appspot.com', issuer: 'WR2', validTo: '2026-12-29T08:00:00Z' },
        { role: 'intermediate', subject: 'WR2', issuer: 'GTS Root R1', validTo: '2029-02-20T14:00:00Z' },
        { role: 'root', subject: 'GTS Root R1', issuer: 'GTS Root R1 (self-signed)', validTo: '2036-06-22T00:00:00Z' },
      ],
      ct: { status: 'not_checked', note: 'Skipped.' },
      revocation: { status: 'not_checked' },
    },
    securityHeaders: {
      status: 'completed',
      httpsRedirect: null,
      headers: [
        { name: 'Strict-Transport-Security', present: true, value: 'max-age=31536000' },
        { name: 'Content-Security-Policy', present: false, recommendation: 'Define a restrictive CSP.' },
        { name: 'X-Frame-Options', present: true, value: 'SAMEORIGIN' },
        { name: 'X-Content-Type-Options', present: true, value: 'nosniff' },
        { name: 'Referrer-Policy', present: false },
      ],
      cookies: [],
    },
    explanation: {
      source: 'template',
      summary:
        'Google Safe Browsing reports this exact URL as a social-engineering (phishing) page, which is a confirmed threat intelligence match. The site has a valid TLS certificate, but that only means the connection is encrypted — it does not make the page trustworthy. This specific URL is Google\'s official test page, used here to demonstrate how a confirmed match is reported.',
      keyPoints: [
        'Confirmed match: Google Safe Browsing → SOCIAL_ENGINEERING.',
        'Valid HTTPS does not offset a confirmed threat match.',
      ],
    },
    recommendations: [
      'Do not enter any personal information, passwords or OTPs on this page.',
      'Close the page and do not download anything from it.',
      'If you reached it from a message or email, report and delete that message.',
    ],
    limitations: ['Certificate Transparency lookup was skipped.', 'Revocation status was not checked.'],
    registry: baseRegistry(),
  };
}

// ---------------------------------------------------------------------------
export function phishingMessageFixture(text) {
  const highlights = highlightsFor(text, [
    { phrase: 'URGENT', tactic: 'urgency' },
    { phrase: 'Your SBI account has been suspended', tactic: 'account_suspension' },
    { phrase: 'SBI', tactic: 'impersonation' },
    { phrase: 'within 24 hours', tactic: 'urgency' },
    { phrase: 'permanently blocked', tactic: 'threat' },
    { phrase: 'http://sbi-kyc-update.example/verify', tactic: 'suspicious_link' },
    { phrase: 'enter your OTP', tactic: 'otp_request' },
    { phrase: 'password', tactic: 'password_request' },
    { phrase: 'cashback reward of Rs 5,000', tactic: 'fake_reward' },
  ]).filter((h, i, arr) => !arr.some((o, j) => j !== i && o.start <= h.start && o.end >= h.end && (o.end - o.start) > (h.end - h.start)));

  return {
    type: 'message',
    target: { display: 'Submitted message (content not stored on-chain)' },
    classification: 'high_risk',
    confidence: 'medium',
    heuristicScore: 82,
    coverage: { completed: 3, total: 4 },
    checks: [
      { id: 'phishing_lang', name: 'Phishing language analysis', source: 'Internal phishing engine', status: 'completed' },
      { id: 'indicators', name: 'Indicator extraction', source: 'Internal phishing engine', status: 'completed' },
      { id: 'gsb', name: 'Google Safe Browsing (extracted URLs)', source: 'Google Safe Browsing', status: 'no_match' },
      { id: 'urlhaus', name: 'URLhaus (extracted URLs)', source: 'URLhaus', status: 'unavailable', detail: 'Provider not configured.' },
    ],
    findings: [
      {
        id: 'f1',
        title: 'Requests OTP and password',
        description: 'The message asks the reader to enter an OTP and password. Legitimate banks never request these through a link in a message.',
        severity: 'high',
        category: 'heuristic',
        source: 'Internal phishing engine',
        checkId: 'phishing_lang',
        evidence: { Phrases: '"enter your OTP", "password"' },
      },
      {
        id: 'f2',
        title: 'Bank impersonation with suspension threat',
        description: 'Claims to be from SBI and threatens account suspension and permanent blocking to create fear.',
        severity: 'high',
        category: 'heuristic',
        source: 'Internal phishing engine',
        checkId: 'phishing_lang',
        evidence: { Brand: 'SBI', Tactics: 'impersonation, account suspension, threat' },
      },
      {
        id: 'f3',
        title: 'Artificial urgency',
        description: '"URGENT" and a 24-hour deadline pressure the reader to act before thinking.',
        severity: 'medium',
        category: 'heuristic',
        source: 'Internal phishing engine',
        checkId: 'phishing_lang',
        evidence: { Phrases: '"URGENT", "within 24 hours"' },
      },
      {
        id: 'f4',
        title: 'Link domain does not belong to the claimed brand',
        description: 'The link points to sbi-kyc-update.example, which is not an official SBI domain.',
        severity: 'high',
        category: 'heuristic',
        source: 'Internal phishing engine',
        checkId: 'indicators',
        evidence: { Domain: 'sbi-kyc-update.example' },
      },
      {
        id: 'f5',
        title: 'Unrelated reward lure',
        description: 'A cashback reward is added to an account-security message — a mixed lure common in fraud.',
        severity: 'medium',
        category: 'heuristic',
        source: 'Internal phishing engine',
        checkId: 'phishing_lang',
        evidence: { Phrase: '"cashback reward of Rs 5,000"' },
      },
    ],
    message: {
      highlights,
      indicators: {
        urls: ['http://sbi-kyc-update.example/verify'],
        domains: ['sbi-kyc-update.example'],
        emails: [],
        phones: [],
      },
      tactics: [
        { key: 'urgency', count: 2 },
        { key: 'account_suspension', count: 1 },
        { key: 'impersonation', count: 1 },
        { key: 'threat', count: 1 },
        { key: 'otp_request', count: 1 },
        { key: 'password_request', count: 1 },
        { key: 'suspicious_link', count: 1 },
        { key: 'fake_reward', count: 1 },
      ],
    },
    explanation: {
      source: 'template',
      summary:
        'This message uses a classic bank-phishing pattern: it impersonates SBI, threatens to suspend the account, sets a 24-hour deadline, and asks you to enter your OTP and password through a link that does not belong to SBI. No threat intelligence provider has listed the link yet, so the High Risk rating is based on language and indicator analysis, not a confirmed match.',
      keyPoints: [
        'Credential and OTP request through a link.',
        'Impersonation combined with fear (suspension) and urgency.',
        'Link domain unrelated to the claimed sender.',
      ],
    },
    recommendations: [
      'Do not click the link and never share your OTP or password.',
      'Contact your bank using the number on your card or its official website.',
      'Report the message to your bank and to cybercrime.gov.in.',
      'Delete the message after reporting it.',
    ],
    limitations: [
      'URLhaus was not configured, so extracted URLs were checked against one provider only.',
      'Sender identity cannot be verified from message text alone.',
    ],
    registry: baseRegistry(),
  };
}

// ---------------------------------------------------------------------------
export function legitMessageFixture() {
  return {
    type: 'message',
    target: { display: 'Submitted message (content not stored on-chain)' },
    classification: 'low_risk',
    confidence: 'medium',
    heuristicScore: 3,
    coverage: { completed: 2, total: 2 },
    checks: [
      { id: 'phishing_lang', name: 'Phishing language analysis', source: 'Internal phishing engine', status: 'completed' },
      { id: 'indicators', name: 'Indicator extraction', source: 'Internal phishing engine', status: 'completed', detail: 'No URLs, emails or phone numbers found.' },
      { id: 'gsb', name: 'Google Safe Browsing (extracted URLs)', source: 'Google Safe Browsing', status: 'not_checked', detail: 'No URLs to check.' },
    ],
    findings: [
      {
        id: 'f1',
        title: 'No suspicious tactics detected',
        description: 'No urgency, threats, credential requests, payment requests or links were found.',
        severity: 'info',
        category: 'informational',
        source: 'Internal phishing engine',
        checkId: 'phishing_lang',
        evidence: { Tactics: 'None' },
      },
    ],
    message: { highlights: [], indicators: { urls: [], domains: [], emails: [], phones: [] }, tactics: [] },
    explanation: {
      source: 'template',
      summary:
        'This reads as an ordinary scheduling message. It contains no links, no requests for credentials or money, and no pressure tactics. That makes it low risk, though CYBERLENS cannot confirm who actually sent it.',
      keyPoints: ['No links or contact indicators.', 'No credential, OTP or payment requests.'],
    },
    recommendations: ['If anything about the sender seems unusual, confirm with them directly.'],
    limitations: ['Sender identity cannot be verified from message text alone.'],
    registry: baseRegistry(),
  };
}

// ---------------------------------------------------------------------------
export function unconnectedFixture(type, targetDisplay) {
  return {
    type,
    target: { display: targetDisplay },
    classification: 'inconclusive',
    confidence: 'low',
    heuristicScore: null,
    coverage: { completed: 0, total: type === 'url' ? 6 : 3 },
    checks: (type === 'url'
      ? [
          ['url_analysis', 'URL structure analysis', 'Internal URL analysis'],
          ['gsb', 'Google Safe Browsing', 'Google Safe Browsing'],
          ['urlhaus', 'URLhaus', 'URLhaus'],
          ['tls', 'TLS inspection', 'TLS inspection'],
          ['ct', 'Certificate Transparency', 'crt.sh'],
          ['headers', 'HTTP security headers', 'HTTP security header inspection'],
        ]
      : [
          ['phishing_lang', 'Phishing language analysis', 'Internal phishing engine'],
          ['indicators', 'Indicator extraction', 'Internal phishing engine'],
          ['gsb', 'Google Safe Browsing (extracted URLs)', 'Google Safe Browsing'],
        ]
    ).map(([id, name, source]) => ({ id, name, source, status: 'unavailable', detail: 'Backend not connected (demo mode).' })),
    findings: [],
    redirectChain: [],
    tls: type === 'url' ? { status: 'unavailable', note: 'Backend not connected (demo mode).' } : undefined,
    securityHeaders: type === 'url' ? { status: 'unavailable', note: 'Backend not connected (demo mode).', headers: [] } : undefined,
    message: type === 'message' ? { highlights: [], indicators: { urls: [], domains: [], emails: [], phones: [] }, tactics: [] } : undefined,
    explanation: {
      source: 'template',
      summary:
        'No checks could run because the CYBERLENS backend is not connected. This target has not been assessed. An inconclusive result must not be read as safe. Try one of the sample cases, or connect the backend to run a real investigation.',
      keyPoints: [],
    },
    recommendations: ['Treat this target with caution until a full investigation can run.'],
    limitations: ['All checks were unavailable in demo mode.'],
    registry: baseRegistry(),
  };
}

export function pickFixture(payload) {
  if (payload.type === 'url') {
    const t = payload.target.trim();
    if (t === SAMPLE_URLS[0].value || /^https?:\/\/(www\.)?example\.com\/?$/i.test(t)) return legitUrlFixture(t);
    if (t === SAMPLE_URLS[1].value) return suspiciousUrlFixture(t);
    if (t === SAMPLE_URLS[2].value) return gsbTestFixture(t);
    return unconnectedFixture('url', t);
  }
  const c = payload.content.trim();
  if (c === SAMPLE_MESSAGES[0].value) return phishingMessageFixture(c);
  if (c === SAMPLE_MESSAGES[1].value) return legitMessageFixture();
  return unconnectedFixture('message', 'Submitted message');
}

export { DEMO_SOURCE_NOTE };
