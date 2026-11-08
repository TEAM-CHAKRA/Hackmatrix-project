import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { env } from './config/env.js';
import { errorHandler } from './middleware/errorHandler.js';
import { sessionMiddleware } from './middleware/session.js';
import { sendError } from './utils/response.js';
import { ERROR_CODES } from './config/constants.js';

import healthRoutes from './routes/healthRoutes.js';
import investigationRoutes from './routes/investigationRoutes.js';
import registryRoutes from './routes/registryRoutes.js';
import communityRoutes from './routes/communityRoutes.js';
import authRoutes from './routes/authRoutes.js';

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', env.TRUST_PROXY);

// Security headers (JSON API: nothing should ever be rendered or framed)
app.use(
  helmet({
    contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    crossOriginResourcePolicy: { policy: 'same-site' },
  })
);

// CORS: explicit allow-list from FRONTEND_URL, credentials allowed, never "*"
app.use(
  cors({
    origin: (origin, cb) => cb(null, !origin ? false : env.FRONTEND_ORIGINS.includes(origin) ? origin : false),
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
    maxAge: 600,
  })
);

// Root welcome / ping
app.get('/', (req, res) => {
  res.json({
    name: 'CYBERLENS API Backend',
    version: '1.0.0',
    contractVersion: 'v0.1',
    status: 'operational',
    endpoints: '/api/health',
  });
});

// Health first: liveness must not depend on body parsing or the session store
app.use('/api', healthRoutes);

// Body parsing and sessions for everything else under /api
app.use('/api', express.json({ limit: env.JSON_BODY_LIMIT }));
app.use('/api', sessionMiddleware);

app.use('/api', investigationRoutes);
app.use('/api', registryRoutes);
app.use('/api', communityRoutes);
app.use('/api', authRoutes);

// Catch-all 404 for unmapped routes
app.use((req, res) => {
  return sendError(res, {
    code: ERROR_CODES.NOT_FOUND,
    message: `Cannot ${req.method} ${req.path} - endpoint does not exist.`,
  }, 404);
});

// Global Error Handling Middleware
app.use(errorHandler);

export default app;
