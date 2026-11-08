import { sendError } from '../utils/response.js';
import { ERROR_CODES } from '../config/constants.js';

/**
 * Startup gate. The server starts listening immediately (so the hosting
 * platform sees it as up and /api/health/live answers), while it connects to
 * the database and prepares the admin account in the background. Requests that
 * arrive during those seconds wait here until startup finishes, instead of
 * failing. Open by default: only server.js closes it (tests never do).
 */
let ready = true;
let waiters = [];

export function beginStartup() {
  ready = false;
}

export function finishStartup() {
  ready = true;
  waiters.splice(0).forEach((resolve) => resolve(true));
}

export function isStarting() {
  return !ready;
}

const MAX_WAIT_MS = 20000; // below the ~30 s a hosting proxy waits

export function startupGate(req, res, next) {
  if (ready) return next();
  let resolveWait;
  const timer = setTimeout(() => resolveWait(false), MAX_WAIT_MS);
  new Promise((resolve) => {
    resolveWait = resolve;
    waiters.push(resolve);
  }).then((ok) => {
    clearTimeout(timer);
    waiters = waiters.filter((w) => w !== resolveWait);
    if (ok) return next();
    return sendError(
      res,
      { code: ERROR_CODES.SERVER_STARTING, message: 'The server is starting up. Please try again in a moment.', details: {} },
      503
    );
  });
}
