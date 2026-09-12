import { Router } from 'express';
import authRoutes from './authRoutes.js';
import scanRoutes from './scanRoutes.js';
import protectionRoutes from './protectionRoutes.js';
import { successResponse } from '../utils/apiResponse.js';

const router = Router();

// Health check endpoint
router.get('/health', (req, res) => {
  return successResponse(res, 200, 'ThreatLens API is operational', {
    service: 'ThreatLens AI - Enterprise Security & Protection Engine',
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// Mount modular sub-routers
router.use('/auth', authRoutes);
router.use('/scan', scanRoutes);
router.use('/scans', scanRoutes);
router.use('/protection', protectionRoutes);

export default router;
