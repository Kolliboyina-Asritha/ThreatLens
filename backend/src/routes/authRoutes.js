import { Router } from 'express';
import {
  register,
  login,
  refresh,
  logout,
  getMe,
  authorizeExtension,
  exchangeExtensionCode,
  refreshExtensionToken,
  logoutExtension
} from '../controllers/authController.js';
import { authenticate } from '../middleware/auth.js';
import { authLimiter } from '../middleware/rateLimiter.js';

const router = Router();

// Standard Web Authentication Routes (Cookie-based Refresh)
router.post('/register', authLimiter, register);
router.post('/login', authLimiter, login);
router.post('/refresh', refresh);
router.post('/logout', logout);
router.get('/me', authenticate, getMe);

// Dedicated Chrome Extension Authentication Routes
router.post('/extension/authorize', authenticate, authLimiter, authorizeExtension);
router.post('/extension/exchange', authLimiter, exchangeExtensionCode);
router.post('/extension/refresh', authLimiter, refreshExtensionToken);
router.post('/extension/logout', logoutExtension);

export default router;

