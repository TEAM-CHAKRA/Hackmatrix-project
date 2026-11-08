import { Router } from 'express';
import { getHealth, getLiveness, getReadiness } from '../controllers/healthController.js';

const router = Router();

router.get('/health', getHealth); // contract: provider status (ok | degraded)
router.get('/health/live', getLiveness); // process liveness
router.get('/health/ready', getReadiness); // repository + session + config

export default router;
