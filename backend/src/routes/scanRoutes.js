import { Router } from 'express';
import {
  scanUrl,
  getScans,
  getScanById,
  deleteScan
} from '../controllers/scanController.js';
import { authenticate } from '../middleware/auth.js';
import { scanLimiter } from '../middleware/rateLimiter.js';

const router = Router();

// Scanning endpoint
router.post('/url', authenticate, scanLimiter, scanUrl);

// Scan history and management
router.get('/', authenticate, getScans);
router.get('/:id', authenticate, getScanById);
router.delete('/:id', authenticate, deleteScan);

export default router;
