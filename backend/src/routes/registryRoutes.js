import { Router } from 'express';
import { registerReport, verifyReport, listRegistry, registerSchema, verifySchema } from '../controllers/registryController.js';
import { validate } from '../middleware/validate.js';
import { registryLimiter, verifyLimiter } from '../middleware/rateLimiter.js';

const router = Router();

// Public: anyone holding a report link may anchor it (idempotent, rate-limited:
// each write costs gas). Verification and the feed are read-only.
router.post('/registry/register', registryLimiter, validate(registerSchema), registerReport);
router.post('/registry/verify', verifyLimiter, validate(verifySchema), verifyReport);
router.get('/registry', listRegistry);

export default router;
