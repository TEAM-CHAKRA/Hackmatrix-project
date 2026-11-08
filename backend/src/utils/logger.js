/**
 * Structured, sanitized logger that redacts secrets and auth tokens.
 */
function sanitize(obj) {
  if (typeof obj === 'string') {
    return obj
      .replace(/(token|session|auth|password|secret|key|privatekey)=([^\s&]+)/gi, '$1=[redacted]')
      .replace(/(Bearer\s+)[A-Za-z0-9\-._~+/]+=*/gi, '$1[redacted]');
  }
  if (typeof obj === 'object' && obj !== null) {
    if (Array.isArray(obj)) return obj.map(sanitize);
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      if (/password|secret|token|privatekey|authorization/i.test(key)) {
        sanitized[key] = '[redacted]';
      } else {
        sanitized[key] = sanitize(value);
      }
    }
    return sanitized;
  }
  return obj;
}

export const logger = {
  info: (msg, meta = {}) => {
    console.log(`[INFO] ${new Date().toISOString()} - ${sanitize(msg)}`, Object.keys(meta).length ? sanitize(meta) : '');
  },
  warn: (msg, meta = {}) => {
    console.warn(`[WARN] ${new Date().toISOString()} - ${sanitize(msg)}`, Object.keys(meta).length ? sanitize(meta) : '');
  },
  error: (msg, meta = {}) => {
    console.error(`[ERROR] ${new Date().toISOString()} - ${sanitize(msg)}`, Object.keys(meta).length ? sanitize(meta) : '');
  },
  debug: (msg, meta = {}) => {
    if (process.env.NODE_ENV === 'development' || process.env.LOG_LEVEL === 'debug') {
      console.debug(`[DEBUG] ${new Date().toISOString()} - ${sanitize(msg)}`, Object.keys(meta).length ? sanitize(meta) : '');
    }
  },
};

