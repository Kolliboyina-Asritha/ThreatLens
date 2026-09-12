import { Router } from 'express';
import { authenticate } from '../middleware/auth.js';
import { scanLimiter } from '../middleware/rateLimiter.js';
import {
  getPolicy,
  updatePolicy,
  evaluateUrl,
  getEvents,
  getEventStats,
  addAllowlistEntry,
  removeAllowlistEntry,
  addBlocklistEntry,
  removeBlocklistEntry,
  recordOverride,
  removeOverride
} from '../controllers/protectionController.js';

const router = Router();

// Enforce authentication across all protection endpoints
router.use(authenticate);

// Protection Policy Configuration
router.get('/policy', getPolicy);
router.put('/policy', updatePolicy);
router.patch('/policy', updatePolicy);

// Protection Evaluation & Threat Checking
router.post('/evaluate', scanLimiter, evaluateUrl);
router.post('/check', scanLimiter, evaluateUrl); // Alias for Extension and API clients

// Security Events & Audit Ledger
router.get('/events', getEvents);
router.get('/events/stats', getEventStats);

// Allowlist & Blocklist Management
router.post('/allowlist', addAllowlistEntry);
router.delete('/allowlist/:id', removeAllowlistEntry);

router.post('/blocklist', addBlocklistEntry);
router.delete('/blocklist/:id', removeBlocklistEntry);

// Reversible User Overrides
router.post('/override', recordOverride);
router.delete('/override/:id?', removeOverride);

export default router;
