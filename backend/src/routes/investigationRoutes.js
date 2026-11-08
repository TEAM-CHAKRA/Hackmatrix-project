import { Router } from 'express';
import { createInvestigation, getInvestigation, createInvestigationSchema } from '../controllers/investigationController.js';
import { validate } from '../middleware/validate.js';
import { investigationLimiter } from '../middleware/rateLimiter.js';

const router = Router();

router.post('/investigations', investigationLimiter, validate(createInvestigationSchema), createInvestigation);
router.get('/investigations/:id', getInvestigation);

export default router;

