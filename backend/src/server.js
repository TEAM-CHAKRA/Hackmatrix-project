import app from './app.js';
import { env } from './config/env.js';
import { logger } from './utils/logger.js';
import { authService } from './services/auth/authService.js';
import { sessionStore } from './services/auth/sessionStore.js';
import { blockchainService } from './services/blockchainService.js';
import { repository } from './store/repository.js';
import { checkSupabaseSchema, failInterruptedInvestigations } from './store/dbCheck.js';

const PORT = env.PORT || 4000;

if (env.SESSION_SECRET_EPHEMERAL) {
  logger.warn('SESSION_SECRET not set: using a random per-process secret (everyone is signed out on restart).');
}

async function start() {
  // Database: confirm Supabase is reachable and set up before serving anything.
  if (repository.kind === 'supabase') {
    logger.info('🗄️  Connecting to Supabase…');
    const { ok, checks } = await checkSupabaseSchema(repository);
    if (!ok) {
      logger.error('🗄️  Supabase is not ready:');
      for (const c of checks.filter((x) => !x.ok)) logger.error(`   ✖ ${c.name}: ${c.detail}`);
      logger.error('Fix the items above (see backend/docs/DATABASE.md), then start again. Run `npm run db:check` to re-test.');
      process.exit(1);
    }
    logger.info('🗄️  Database: Supabase (all tables ready)');
    try {
      const n = await failInterruptedInvestigations(repository);
      if (n) logger.info(`Marked ${n} scan(s) interrupted by the last restart as failed.`);
    } catch (err) {
      logger.warn(`Could not tidy interrupted scans: ${err.message}`);
    }
  } else {
    logger.info('🗄️  Database: in-memory (data resets on restart; set SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY to persist)');
  }

  // Optional admin account from ADMIN_EMAIL / ADMIN_PASSWORD (before listening).
  if (env.ADMIN_EMAIL) {
    try {
      await authService.bootstrapAdmin({ email: env.ADMIN_EMAIL, password: env.ADMIN_PASSWORD, fullName: env.ADMIN_NAME });
      logger.info('Admin account ready.');
    } catch (err) {
      logger.error(`Admin bootstrap failed: ${err.message}`);
      process.exit(1);
    }
  }

  const chain = blockchainService.describe();
  logger.info(
    chain.configured
      ? `⛓️  Blockchain: ${chain.network} (contract ${chain.contractAddress})`
      : '⛓️  Blockchain: not configured (registration disabled; see docs/SETUP.md)'
  );

  const server = app.listen(PORT, () => {
    logger.info(`🚀 CYBERLENS Backend listening on http://localhost:${PORT}`);
    logger.info(`🔗 Base API path: http://localhost:${PORT}/api`);
    logger.info(`🩺 Health check: http://localhost:${PORT}/api/health`);
  });

  function handleShutdown(signal) {
    logger.info(`Received ${signal}. Shutting down CYBERLENS backend gracefully...`);
    server.close(() => {
      sessionStore.close();
      logger.info('HTTP server closed.');
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000).unref();
  }

  process.on('SIGTERM', () => handleShutdown('SIGTERM'));
  process.on('SIGINT', () => handleShutdown('SIGINT'));
}

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Promise Rejection:', { reason: reason?.message || String(reason) });
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', { error: err.message, stack: err.stack });
});

start();
