import { verifyAccessToken } from '../services/authService.js';
import { User } from '../models/User.js';
import { errorResponse } from '../utils/apiResponse.js';

export const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return errorResponse(res, 401, 'Authentication required. No valid Bearer token provided.');
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return errorResponse(res, 401, 'Authentication token is missing.');
    }

    let decoded;
    try {
      decoded = verifyAccessToken(token);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return errorResponse(res, 401, 'Access token has expired. Please refresh your token.');
      }
      return errorResponse(res, 401, 'Invalid authentication token.');
    }

    const user = await User.findById(decoded.sub);
    if (!user) {
      return errorResponse(res, 401, 'User account associated with token no longer exists.');
    }

    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
};
