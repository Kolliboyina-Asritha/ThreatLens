import rateLimit from 'express-rate-limit';
import { errorResponse } from '../utils/apiResponse.js';

const rateLimitHandler = (req, res, next, options) => {
  return errorResponse(res, 429, options.message || 'Too many requests. Please slow down and try again later.');
};

const isTestEnv = () => process.env.NODE_ENV === 'test';

// General API rate limiter (200 requests per 15 minutes per IP)
export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  skip: isTestEnv,
  message: 'Global rate limit exceeded. Please try again later.',
  handler: rateLimitHandler
});

// Strict rate limiter for Authentication endpoints (20 attempts per 15 minutes per IP)
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  skip: isTestEnv,
  message: 'Too many authentication attempts from this IP address. Please try again after 15 minutes.',
  handler: rateLimitHandler
});

// Scanning rate limiter (30 scans per minute per IP)
export const scanLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  skip: isTestEnv,
  message: 'Scan rate limit exceeded. Please wait a moment before initiating another scan.',
  handler: rateLimitHandler
});
