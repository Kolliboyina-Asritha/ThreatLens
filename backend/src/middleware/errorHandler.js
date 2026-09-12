import { ZodError } from 'zod';
import { URLNormalizationError } from '../services/urlNormalizer.js';
import { errorResponse } from '../utils/apiResponse.js';

export const notFoundHandler = (req, res, next) => {
  return errorResponse(res, 404, `Endpoint ${req.method} ${req.originalUrl} not found`);
};

export const errorHandler = (err, req, res, next) => {
  // Log internal error for debugging (without leaking credentials)
  console.error(`[Error] [${req.method} ${req.url}]:`, err.message || err);

  // 1. Zod Validation Errors
  if (err instanceof ZodError) {
    const formattedErrors = err.errors.map((e) => ({
      field: e.path.join('.'),
      message: e.message
    }));
    return errorResponse(res, 400, 'Validation failed for submitted data', formattedErrors);
  }

  // 2. Custom URL Normalization Errors
  if (err instanceof URLNormalizationError) {
    return errorResponse(res, 400, err.message, { code: err.code });
  }

  // 3. Mongoose Duplicate Key Error (E.g. Duplicate Email)
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue || {})[0] || 'field';
    return errorResponse(res, 409, `An account with this ${field} already exists.`);
  }

  // 4. Mongoose Validation or Cast Error
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map((val) => val.message);
    return errorResponse(res, 400, 'Database validation error', messages);
  }

  if (err.name === 'CastError') {
    return errorResponse(res, 400, `Invalid ID format for resource: ${err.value}`);
  }

  // 5. JWT Errors
  if (err.name === 'JsonWebTokenError') {
    return errorResponse(res, 401, 'Invalid authentication token.');
  }
  if (err.name === 'TokenExpiredError') {
    return errorResponse(res, 401, 'Authentication token has expired.');
  }

  // 6. Generic Internal Server Error (Sanitized)
  const statusCode = typeof err.statusCode === 'number' ? err.statusCode : 500;
  const message = statusCode === 500 ? 'Internal server error occurred.' : (err.message || 'An unexpected error occurred.');

  return errorResponse(res, statusCode, message);
};
