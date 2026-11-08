import { Router } from 'express';
import {
  submitCommunityReport,
  listCommunityReports,
  getCommunityReport,
  voteCommunityReport,
  updateCommunityReportStatus,
  submitCommunityReportSchema,
  voteCommunityReportSchema,
  updateStatusSchema,
} from '../controllers/communityController.js';
import { validate } from '../middleware/validate.js';
import { communityLimiter, communityVoteLimiter } from '../middleware/rateLimiter.js';
import { csrfProtection } from '../middleware/csrf.js';
import { loadAuth, requireRole } from '../middleware/auth.js';

const router = Router();

// Anonymous submissions and votes are allowed (rate-limited). CSRF applies
// because a signed-in user's session is attached to these actions.
router.post('/community/reports', communityLimiter, csrfProtection, loadAuth, validate(submitCommunityReportSchema), submitCommunityReport);
router.get('/community/reports', loadAuth, listCommunityReports);
router.get('/community/reports/:id', loadAuth, getCommunityReport);
router.post('/community/reports/:id/vote', communityVoteLimiter, csrfProtection, loadAuth, validate(voteCommunityReportSchema), voteCommunityReport);
router.patch('/community/reports/:id/status', requireRole('admin'), csrfProtection, validate(updateStatusSchema), updateCommunityReportStatus);

export default router;
