import { checkGoogleSafeBrowsing } from './threatIntel/gsbClient.js';
import { checkUrlhaus } from './threatIntel/urlhausClient.js';

/**
 * Phase 4 — Phishing language analysis for MESSAGE investigations.
 *
 * Four fixed checks (coverage total = 4):
 *   indicators   URLs, domains, emails and phone numbers in the text
 *   tactics      psychological-pressure / phishing tactics with highlight offsets
 *   threat_intel Google Safe Browsing + URLhaus lookups of the extracted links
 *   links        claimed brand vs link domain, raw IPs, shorteners, punycode, no HTTPS
 *
 * Highlights are { start, end, phrase, tactic } offsets into the ORIGINAL text,
 * non-overlapping (higher-severity / longer spans win). The text itself is never
 * sent to external services: only the extracted URLs go to GSB / URLhaus.
 */

const MAX_URLS_CHECKED = 5;

// ---------------------------------------------------------------------------
// Brands commonly impersonated in India and globally, with official domains.
// ---------------------------------------------------------------------------
export const BRANDS = [
  { name: 'SBI', re: /\b(SBI|State Bank of India|YONO)\b/, domains: ['sbi.co.in', 'onlinesbi.sbi', 'sbi', 'onlinesbi.com', 'sbicard.com', 'yonosbi.com'] },
  { name: 'HDFC Bank', re: /\bHDFC\b/i, domains: ['hdfcbank.com', 'hdfc.com', 'hdfcbank.net'] },
  { name: 'ICICI Bank', re: /\bICICI\b/i, domains: ['icicibank.com', 'icici.com', 'icicidirect.com'] },
  { name: 'Axis Bank', re: /\bAxis Bank\b/i, domains: ['axisbank.com', 'axis.bank.in'] },
  { name: 'Kotak', re: /\bKotak\b/i, domains: ['kotak.com', 'kotaksecurities.com'] },
  { name: 'Paytm', re: /\bPaytm\b/i, domains: ['paytm.com', 'paytmbank.com', 'paytm.in'] },
  { name: 'PhonePe', re: /\bPhone ?Pe\b/i, domains: ['phonepe.com'] },
  { name: 'Google Pay', re: /\b(Google Pay|GPay)\b/i, domains: ['google.com', 'pay.google.com', 'g.co'] },
  { name: 'Amazon', re: /\bAmazon\b/i, domains: ['amazon.in', 'amazon.com', 'amazon.co.uk', 'amzn.to', 'amzn.in'] },
  { name: 'Flipkart', re: /\bFlipkart\b/i, domains: ['flipkart.com', 'fkrt.it'] },
  { name: 'PayPal', re: /\bPay ?Pal\b/i, domains: ['paypal.com', 'paypal.me'] },
  { name: 'Apple', re: /\b(Apple ?ID|iCloud|Apple)\b/, domains: ['apple.com', 'icloud.com'] },
  { name: 'Microsoft', re: /\b(Microsoft|Outlook|Office ?365)\b/i, domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com'] },
  { name: 'Netflix', re: /\bNetflix\b/i, domains: ['netflix.com'] },
  { name: 'WhatsApp', re: /\bWhats ?App\b/i, domains: ['whatsapp.com', 'wa.me'] },
  { name: 'Income Tax Department', re: /\b(Income Tax|ITR refund|IT department)\b/i, domains: ['incometax.gov.in', 'incometaxindia.gov.in'] },
  { name: 'UIDAI / Aadhaar', re: /\b(Aadhaar|Aadhar|UIDAI)\b/i, domains: ['uidai.gov.in', 'myaadhaar.uidai.gov.in'] },
  { name: 'RBI', re: /\b(RBI|Reserve Bank)\b/, domains: ['rbi.org.in'] },
  { name: 'India Post', re: /\bIndia ?Post\b/i, domains: ['indiapost.gov.in'] },
  { name: 'FedEx', re: /\bFedEx\b/i, domains: ['fedex.com'] },
  { name: 'DHL', re: /\bDHL\b/, domains: ['dhl.com', 'dhl.co.in'] },
];

// ---------------------------------------------------------------------------
// Tactic patterns. Higher priority wins when highlights overlap.
// ---------------------------------------------------------------------------
const TACTICS = [
  {
    key: 'otp_request', priority: 9,
    patterns: [
      /\b(share|send|enter|provide|tell|give|forward|confirm|verify|type)\s+(us\s+)?(your\s+|the\s+)?(otp|one[- ]time (pass(word|code))|verification code|security code|cvv|atm pin|upi pin|m-?pin)\b/gi,
      /\b(otp|one[- ]time password)\b/gi,
    ],
  },
  {
    key: 'password_request', priority: 9,
    patterns: [
      /\b(enter|share|send|confirm|verify|update|provide|reset|re-?enter|type)\s+(your\s+)?(password|passcode|login (details|credentials)|net ?banking (password|credentials|details)|credentials)\b/gi,
      /\bpassword\b/gi,
    ],
  },
  {
    key: 'payment_request', priority: 8,
    patterns: [
      /\b(pay|transfer|send|deposit)\s+(a\s+|the\s+)?(small\s+)?((rs\.?|inr|usd)\s?|₹\s?|\$\s?)?\d[\d,]*(\.\d+)?(\s?(rs|rupees|inr|usd))?/gi,
      /\b(processing|registration|delivery|customs|clearance|verification|activation|release) (fee|charge|charges)\b/gi,
      /\b(gift ?cards?|bitcoin|crypto(currency)? wallet|upi collect request)\b/gi,
      /\bpay (now|immediately|today|to (avoid|release|unlock))\b/gi,
    ],
  },
  {
    key: 'account_suspension', priority: 7,
    patterns: [
      /\b(your\s+)?(account|card|sim|wallet|kyc|upi|number|profile|access)\s+(has been|is|will be|was|may be)\s+(temporarily\s+|permanently\s+)?(suspended|blocked|locked|deactivated|disabled|frozen|closed|restricted|expired|on hold|put on hold)\b/gi,
      /\b(suspended|deactivated|blocked|frozen)\s+(account|card|kyc)\b/gi,
      /\b(kyc|pan|aadhaar)\s+(is\s+)?(expired|pending|incomplete|not updated)\b/gi,
    ],
  },
  {
    key: 'threat', priority: 6,
    patterns: [
      /\b(legal action|police (complaint|case|action)|arrest(ed)?( warrant)?|court (notice|case)|penalty|fine of|lose (access|your account|all (your )?(data|money))|permanently (blocked|deleted|closed|suspended|disabled)|cyber ?crime (case|complaint))\b/gi,
    ],
  },
  {
    key: 'fake_reward', priority: 6,
    patterns: [
      /\b(you('ve| have)? (won|been selected)|congratulations|winner|lucky draw|lottery|jackpot|prize|claim your (reward|prize|gift|refund|cashback)|free (gift|iphone|recharge|voucher))\b/gi,
      /\b(cashback|reward|refund)( reward)? of (rs\.?\s?|₹\s?|inr\s?|\$\s?)?\d[\d,]*/gi,
    ],
  },
  {
    key: 'urgency', priority: 4,
    patterns: [
      /\b(urgent(ly)?|immediately|act now|right away|asap|hurry|last chance|final (notice|warning|reminder)|today only|limited time|don'?t delay|without delay|expires? (today|tonight|soon)|within \d+\s?(hours?|hrs?|minutes?|mins?|days?))\b/gi,
    ],
  },
  {
    key: 'social_engineering', priority: 3,
    patterns: [
      /\b(do not|don'?t) (tell|share (this )?with|inform) anyone\b/gi,
      /\b(keep (this|it) (confidential|secret))\b/gi,
      /\b(click (here|the link|below|on the link)|tap (here|the link))\b/gi,
      /\b(verify|update|confirm|complete|re-?validate) your (identity|account|details|information|kyc|pan|aadhaar|bank details)\b/gi,
      /\b(dear (customer|user|valued customer|account holder|sir\/madam))\b/gi,
    ],
  },
];

const PRIORITY = Object.fromEntries(TACTICS.map((t) => [t.key, t.priority]));
PRIORITY.impersonation = 5;
PRIORITY.suspicious_link = 10;

// ---------------------------------------------------------------------------
// Indicators
// ---------------------------------------------------------------------------
const URL_RE = /\b((?:https?|hxxps?):\/\/[^\s<>"'`]+|www\.[^\s<>"'`]+)/gi;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g;
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.|\[\.\]))+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24})\b/gi;
const PHONE_RE = /(?<![\w\d])(?:\+?\d[\d\s().-]{8,18}\d)(?![\w\d])/g;
const FILE_EXT = /\.(txt|pdf|docx?|xlsx?|pptx?|png|jpe?g|gif|zip|rar|apk|exe|js|html?|php|csv|json|mp4|mp3)$/i;
const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at', 'ow.ly', 'buff.ly', 'rebrand.ly', 't.ly', 'tiny.cc', 'shorte.st', 'v.gd', 'bl.ink']);

function refang(s) {
  return s.replace(/^hxxp/i, 'http').replace(/\[\.\]/g, '.').replace(/\(\.\)/g, '.');
}

function trimUrl(raw) {
  // Drop trailing punctuation that is almost never part of a URL in prose.
  let u = raw.replace(/[.,;:!?)\]}>'"]+$/, '');
  const opens = (u.match(/\(/g) || []).length;
  const closes = (u.match(/\)/g) || []).length;
  if (closes > opens) u = u.replace(/\)+$/, '');
  return u;
}

function parseUrl(u) {
  try {
    const parsed = new URL(/^https?:\/\//i.test(u) ? u : `http://${u}`);
    return parsed;
  } catch {
    return null;
  }
}

/** Remove query values that look sensitive before showing/sending a URL. */
export function safeUrl(u) {
  const p = parseUrl(u);
  if (!p) return u;
  p.username = '';
  p.password = '';
  for (const k of [...p.searchParams.keys()]) {
    if (/token|session|auth|key|pass|code|sig|secret|otp|pin/i.test(k)) p.searchParams.set(k, '[redacted]');
  }
  return p.toString();
}

export function extractIndicators(text) {
  const urls = [];
  const urlSpans = [];
  for (const m of text.matchAll(URL_RE)) {
    const raw = trimUrl(m[0]);
    const normalized = refang(raw);
    const parsed = parseUrl(normalized);
    if (!parsed || !parsed.hostname.includes('.')) continue;
    urlSpans.push({ start: m.index, end: m.index + raw.length, raw, url: parsed.toString(), host: parsed.hostname.toLowerCase() });
    if (!urls.includes(parsed.toString())) urls.push(parsed.toString());
  }

  const emails = [...new Set([...text.matchAll(EMAIL_RE)].map((m) => m[0].toLowerCase()))];
  const emailDomains = new Set(emails.map((e) => e.split('@')[1]));

  const inUrl = (idx) => urlSpans.some((s) => idx >= s.start && idx < s.end);
  const domains = new Set(urlSpans.map((s) => s.host));
  for (const m of text.matchAll(DOMAIN_RE)) {
    if (inUrl(m.index)) continue;
    const d = refang(m[0]).toLowerCase();
    if (FILE_EXT.test(d) || emailDomains.has(d)) continue;
    const before = text[m.index - 1];
    if (before === '@') continue; // part of an email
    domains.add(d);
  }

  const phones = [];
  for (const m of text.matchAll(PHONE_RE)) {
    if (inUrl(m.index)) continue;
    const digits = m[0].replace(/\D/g, '');
    if (digits.length < 10 || digits.length > 15) continue;
    if (/^\d{4}-\d{2}-\d{2}/.test(m[0].trim())) continue; // a date
    const value = m[0].trim();
    if (!phones.includes(value)) phones.push(value);
  }

  return { urls, domains: [...domains], emails, phones, urlSpans };
}

// ---------------------------------------------------------------------------
// Tactics + highlights
// ---------------------------------------------------------------------------
function collectSpans(text) {
  const spans = [];
  for (const t of TACTICS) {
    for (const re of t.patterns) {
      for (const m of text.matchAll(re)) {
        if (!m[0].trim()) continue;
        spans.push({ start: m.index, end: m.index + m[0].length, tactic: t.key });
      }
    }
  }
  return spans;
}

/** Keep non-overlapping spans: higher priority first, then longer. */
export function resolveOverlaps(spans) {
  const ordered = [...spans].sort(
    (a, b) => (PRIORITY[b.tactic] || 0) - (PRIORITY[a.tactic] || 0) || (b.end - b.start) - (a.end - a.start) || a.start - b.start
  );
  const kept = [];
  for (const s of ordered) {
    if (kept.every((k) => s.end <= k.start || s.start >= k.end)) kept.push(s);
  }
  return kept.sort((a, b) => a.start - b.start);
}

function hostMatchesBrand(host, brand) {
  return brand.domains.some((d) => host === d || host.endsWith(`.${d}`));
}

// ---------------------------------------------------------------------------
// Link checks
// ---------------------------------------------------------------------------
function linkFlags(span, claimedBrands) {
  const flags = [];
  const host = span.host;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) flags.push('ip');
  if (SHORTENERS.has(host)) flags.push('shortener');
  if (host.split('.').some((l) => l.startsWith('xn--'))) flags.push('punycode');
  if (!/^https:/i.test(span.url)) flags.push('no_https');
  const mismatched = claimedBrands.filter((b) => !hostMatchesBrand(host, b));
  if (claimedBrands.length && mismatched.length === claimedBrands.length && !SHORTENERS.has(host)) flags.push('brand_mismatch');
  // Brand name inside an unrelated domain, e.g. sbi-kyc-update.example
  const embedded = BRANDS.find((b) => !hostMatchesBrand(host, b) && b.domains.some((d) => host.includes(d.split('.')[0]) && d.split('.')[0].length >= 3));
  if (embedded) flags.push(`brand_in_domain:${embedded.name}`);
  return flags;
}

// ---------------------------------------------------------------------------
// Threat intelligence on extracted URLs
// ---------------------------------------------------------------------------
async function threatIntelForUrls(urls, fetchFn) {
  if (urls.length === 0) {
    return { id: 'threat_intel', name: 'Threat intelligence (extracted links)', source: 'Google Safe Browsing, URLhaus', status: 'not_checked', detail: 'No links found in the message.', findings: [], providers: [] };
  }
  const toCheck = urls.slice(0, MAX_URLS_CHECKED);
  const results = await Promise.all(
    toCheck.map(async (url) => {
      const [gsb, urlhaus] = await Promise.all([
        checkGoogleSafeBrowsing({ url, fetchFn }).catch(() => ({ status: 'error', findings: [] })),
        checkUrlhaus({ url, fetchFn }).catch(() => ({ status: 'error', findings: [] })),
      ]);
      return { url, gsb, urlhaus };
    })
  );

  const ok = (s) => ['completed', 'no_match', 'match_found'].includes(s);
  const providers = [];
  if (results.every((r) => ok(r.gsb.status))) providers.push('Google Safe Browsing');
  if (results.every((r) => ok(r.urlhaus.status))) providers.push('URLhaus');

  const findings = [];
  let n = 0;
  for (const r of results) {
    for (const [prov, res] of [['Google Safe Browsing', r.gsb], ['URLhaus', r.urlhaus]]) {
      if (res.status !== 'match_found') continue;
      for (const f of res.findings || []) {
        n++;
        findings.push({
          ...f,
          id: `f_ti_${n}`,
          checkId: 'threat_intel',
          source: prov,
          evidence: { ...(f.evidence || {}), Link: safeUrl(r.url) },
        });
      }
    }
  }

  const anyMatch = findings.length > 0;
  const anyProvider = results.some((r) => ok(r.gsb.status) || ok(r.urlhaus.status));
  const skipped = urls.length - toCheck.length;
  let status = 'unavailable';
  if (anyMatch) status = 'match_found';
  else if (providers.length > 0) status = 'no_match';
  else if (anyProvider) status = 'no_match';

  const parts = [];
  if (providers.length) parts.push(`Checked ${toCheck.length} link(s) with ${providers.join(' and ')}`);
  else if (!anyProvider) parts.push('No threat intelligence provider could be reached');
  else parts.push(`Checked ${toCheck.length} link(s); some provider lookups failed`);
  if (skipped > 0) parts.push(`${skipped} more link(s) not checked`);

  // A partial check (one provider only) still counts, but is labelled honestly.
  return {
    id: 'threat_intel',
    name: 'Threat intelligence (extracted links)',
    source: 'Google Safe Browsing, URLhaus',
    status,
    detail: `${parts.join('; ')}.`,
    findings,
    providers,
  };
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------
/**
 * @param {object} p
 * @param {string} p.content original submitted text
 * @param {Function} [p.fetchFn]
 * @param {(check: object) => Promise<void>|void} [p.onCheckComplete]
 */
export async function analyzeMessage({ content, fetchFn = globalThis.fetch, onCheckComplete } = {}) {
  const text = String(content || '');
  const emit = async (c) => {
    if (onCheckComplete) await onCheckComplete(c);
    return c;
  };

  // 1. Indicators ----------------------------------------------------------------
  const ind = extractIndicators(text);
  const indicators = { urls: ind.urls.map(safeUrl), domains: ind.domains, emails: ind.emails, phones: ind.phones };
  const indicatorCheck = await emit({
    id: 'indicators',
    name: 'Indicator extraction',
    source: 'Internal phishing engine',
    status: 'completed',
    detail: `${ind.urls.length} link(s), ${ind.domains.length} domain(s), ${ind.emails.length} email(s), ${ind.phones.length} phone number(s).`,
    findings: [],
  });

  // 2. Tactics -------------------------------------------------------------------
  const spans = collectSpans(text);
  const claimedBrands = [];
  for (const b of BRANDS) {
    const re = new RegExp(b.re.source, b.re.flags.includes('g') ? b.re.flags : `${b.re.flags}g`);
    for (const m of text.matchAll(re)) {
      // Skip brand names that only appear inside a URL/domain (handled by links).
      if (ind.urlSpans.some((s) => m.index >= s.start && m.index < s.end)) continue;
      spans.push({ start: m.index, end: m.index + m[0].length, tactic: 'impersonation' });
      if (!claimedBrands.includes(b)) claimedBrands.push(b);
    }
  }

  // 4 (computed early for highlights). Link flags ------------------------------------
  const linkResults = ind.urlSpans.map((s) => ({ ...s, flags: linkFlags(s, claimedBrands) }));
  for (const l of linkResults) {
    if (l.flags.length) spans.push({ start: l.start, end: l.end, tactic: 'suspicious_link' });
  }

  const kept = resolveOverlaps(spans);
  const highlights = kept.map((s) => ({ start: s.start, end: s.end, phrase: text.slice(s.start, s.end), tactic: s.tactic }));
  const counts = {};
  for (const h of highlights) counts[h.tactic] = (counts[h.tactic] || 0) + 1;
  const tactics = Object.entries(counts)
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => (PRIORITY[b.key] || 0) - (PRIORITY[a.key] || 0));
  const has = (k) => Boolean(counts[k]);

  const asksForSomething = has('otp_request') || has('password_request') || has('payment_request');
  const pressure = has('account_suspension') || has('threat');
  const tacticFindings = [];
  const add = (id, title, description, severity, evidenceTactics) =>
    tacticFindings.push({
      id,
      title,
      description,
      severity,
      category: 'heuristic',
      source: 'Internal phishing engine',
      checkId: 'tactics',
      evidence: { Tactics: evidenceTactics.join(', '), Occurrences: String(evidenceTactics.reduce((n, k) => n + (counts[k] || 0), 0)) },
    });

  if (has('otp_request')) add('f_msg_otp', 'Asks for a one-time password, PIN or card code', 'Legitimate banks and services never ask you to share an OTP, PIN or CVV through a message or link.', 'high', ['otp_request']);
  if (has('password_request')) add('f_msg_password', 'Asks for a password or login details', 'Requests for passwords or login credentials through a message are a hallmark of phishing.', 'high', ['password_request']);
  if (has('payment_request')) add('f_msg_payment', 'Asks for money or a fee', 'The message asks for a payment, fee, gift card or crypto transfer, which is common in scams.', 'medium', ['payment_request']);
  if (pressure) add('f_msg_threat', 'Threatens suspension, penalties or loss of access', 'Fear of losing an account or facing penalties is used to push the reader into acting quickly.', 'medium', ['account_suspension', 'threat'].filter(has));
  if (has('fake_reward')) add('f_msg_reward', 'Promises a prize, reward or refund', 'Unexpected rewards are a common lure to make people click or pay.', 'medium', ['fake_reward']);
  if (has('urgency')) {
    add('f_msg_urgency', 'Creates artificial urgency', 'Deadlines and urgent wording pressure the reader to act before thinking.', asksForSomething || pressure || linkResults.length ? 'medium' : 'low', ['urgency']);
  }
  if (has('impersonation') && (asksForSomething || pressure || linkResults.some((l) => l.flags.length))) {
    add('f_msg_impersonation', 'Uses a well-known brand name while asking you to act', `The message names ${claimedBrands.map((b) => b.name).join(', ')} and combines it with requests or pressure typical of impersonation scams.`, 'high', ['impersonation']);
  }
  if (has('social_engineering')) add('f_msg_social', 'Uses generic social-engineering phrasing', 'Generic greetings, "click here" or "verify your account" wording is common in mass phishing.', 'low', ['social_engineering']);

  const tacticsCheck = await emit({
    id: 'tactics',
    name: 'Phishing language analysis',
    source: 'Internal phishing engine',
    status: 'completed',
    detail: tactics.length ? `${tactics.length} tactic type(s) detected.` : 'No phishing tactics detected.',
    findings: tacticFindings,
  });

  // 3. Threat intelligence on links ------------------------------------------------
  const tiCheck = await emit(await threatIntelForUrls(ind.urls, fetchFn));

  // 4. Links -------------------------------------------------------------------------
  const linkFindings = [];
  let li = 0;
  const seen = new Set();
  for (const l of linkResults) {
    if (seen.has(l.url)) continue;
    seen.add(l.url);
    const shown = safeUrl(l.url);
    const push = (suffix, title, description, severity, extra = {}) => {
      li++;
      linkFindings.push({ id: `f_link_${suffix}_${li}`, title, description, severity, category: 'heuristic', source: 'Internal phishing engine', checkId: 'links', evidence: { Link: shown, Domain: l.host, ...extra } });
    };
    if (l.flags.includes('brand_mismatch')) {
      push('mismatch', 'Link does not belong to the brand the message claims to be', `The message mentions ${claimedBrands.map((b) => b.name).join(', ')}, but the link goes to ${l.host}, which is not an official domain of that brand.`, 'high', { 'Claimed brand': claimedBrands.map((b) => b.name).join(', ') });
    } else {
      const embedded = l.flags.find((f) => f.startsWith('brand_in_domain:'));
      if (embedded) push('brandname', 'Link domain contains a brand name but is not that brand', `${l.host} uses the name ${embedded.split(':')[1]} without being an official domain of it.`, 'high');
    }
    if (l.flags.includes('ip')) push('ip', 'Link points to a raw IP address', 'Legitimate organisations link to named domains, not bare IP addresses.', 'high');
    if (l.flags.includes('punycode')) push('punycode', 'Link uses a look-alike (punycode) domain', 'Punycode domains can imitate real brand names with similar-looking characters.', 'high');
    if (l.flags.includes('shortener')) push('short', 'Shortened link hides the real destination', 'Link shorteners hide where the link actually goes.', 'medium');
    if (l.flags.includes('no_https')) push('http', 'Link does not use HTTPS', 'The link is not encrypted; sign-in or payment pages should always use HTTPS.', 'low');
  }

  const linksCheck = await emit({
    id: 'links',
    name: 'Link and brand consistency',
    source: 'Internal phishing engine',
    status: ind.urls.length ? 'completed' : 'not_checked',
    detail: ind.urls.length ? `${ind.urls.length} link(s) inspected.` : 'No links found in the message.',
    findings: linkFindings,
  });

  if (tacticFindings.length === 0 && linkFindings.length === 0 && tiCheck.status !== 'match_found') {
    tacticsCheck.findings.push({
      id: 'f_msg_clean',
      title: 'No phishing tactics detected',
      description: 'No urgency, threats, credential requests, payment requests or risky links were found.',
      severity: 'info',
      category: 'informational',
      source: 'Internal phishing engine',
      checkId: 'tactics',
      evidence: { Tactics: 'none' },
    });
  }

  const checks = [indicatorCheck, tacticsCheck, tiCheck, linksCheck];
  return {
    checks,
    findings: checks.flatMap((c) => c.findings || []),
    message: { highlights, indicators, tactics },
  };
}
