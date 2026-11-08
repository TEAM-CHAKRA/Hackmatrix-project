// Client-side URL helpers. These are for UX only — the backend MUST repeat
// validation and enforce SSRF protection (private IPs, DNS, redirects, ports).

const SENSITIVE_PARAM_PATTERN =
  /^(token|access_token|id_token|auth|code|session|sid|key|apikey|api_key|password|pass|pwd|otp|secret|signature|sig|email|phone|ssn|card)$/i;

export function validateInvestigationUrl(raw) {
  const value = (raw || '').trim();
  if (!value) return { ok: false, error: 'Enter a URL to investigate.' };
  if (value.length > 2048) return { ok: false, error: 'URL is too long (max 2048 characters).' };

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return {
      ok: false,
      error: 'That does not look like a valid URL. Include the scheme, e.g. https://example.com',
    };
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, error: 'Only http:// and https:// URLs can be investigated.' };
  }
  if (!parsed.hostname) return { ok: false, error: 'The URL is missing a hostname.' };
  if (parsed.username || parsed.password) {
    // Still allowed (it's a phishing tactic), but warn the user.
    return { ok: true, value, warning: 'This URL embeds credentials (user@host) — a common deception tactic.' };
  }
  return { ok: true, value };
}

/** Redact sensitive query parameter values for display. */
export function redactUrl(raw) {
  try {
    const u = new URL(raw);
    for (const [k] of u.searchParams) {
      if (SENSITIVE_PARAM_PATTERN.test(k)) u.searchParams.set(k, '[redacted]');
    }
    if (u.password) u.password = '[redacted]';
    return decodeURI(u.toString());
  } catch {
    return raw;
  }
}

export function hostnameOf(raw) {
  try {
    return new URL(raw).hostname;
  } catch {
    return '';
  }
}

export function validateMessage(raw) {
  const value = (raw || '').trim();
  if (!value) return { ok: false, error: 'Paste a message to analyze.' };
  if (value.length < 10) return { ok: false, error: 'Message is too short to analyze meaningfully.' };
  if (value.length > 5000) return { ok: false, error: 'Message is too long (max 5000 characters).' };
  return { ok: true, value };
}
