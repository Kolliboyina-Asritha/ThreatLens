import crypto from 'crypto';
import { User } from '../models/User.js';
import {
  registerSchema,
  loginSchema,
  extensionAuthorizeSchema,
  extensionExchangeSchema,
  extensionRefreshSchema
} from '../validators/authValidators.js';
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  getRefreshTokenCookieOptions
} from '../services/authService.js';
import { AUTH_CONSTANTS } from '../config/constants.js';
import { successResponse, errorResponse } from '../utils/apiResponse.js';

// In-memory store for short-lived, single-use extension authorization codes (60s TTL)
const extensionAuthCodes = new Map();

// Periodic cleanup of expired authorization codes
const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [code, entry] of extensionAuthCodes.entries()) {
    if (entry.expiresAt <= now) {
      extensionAuthCodes.delete(code);
    }
  }
}, 30000);
if (cleanupTimer.unref) cleanupTimer.unref();

export const register = async (req, res, next) => {
  try {
    const validatedData = registerSchema.parse(req.body);

    const existingUser = await User.findOne({ email: validatedData.email });
    if (existingUser) {
      return errorResponse(res, 409, 'An account with this email address already exists.');
    }

    const user = await User.create({
      name: validatedData.name,
      email: validatedData.email,
      password: validatedData.password
    });

    const accessToken = generateAccessToken(user._id.toString(), user.email);
    const refreshToken = generateRefreshToken(user._id.toString());

    res.cookie(
      AUTH_CONSTANTS.REFRESH_COOKIE_NAME,
      refreshToken,
      getRefreshTokenCookieOptions()
    );

    return successResponse(
      res,
      201,
      'User registered successfully.',
      {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          createdAt: user.createdAt
        },
        accessToken
      }
    );
  } catch (error) {
    next(error);
  }
};

export const login = async (req, res, next) => {
  try {
    const validatedData = loginSchema.parse(req.body);

    const user = await User.findOne({ email: validatedData.email });
    if (!user) {
      return errorResponse(res, 401, 'Invalid email or password.');
    }

    const isMatch = await user.comparePassword(validatedData.password);
    if (!isMatch) {
      return errorResponse(res, 401, 'Invalid email or password.');
    }

    const accessToken = generateAccessToken(user._id.toString(), user.email);
    const refreshToken = generateRefreshToken(user._id.toString());

    res.cookie(
      AUTH_CONSTANTS.REFRESH_COOKIE_NAME,
      refreshToken,
      getRefreshTokenCookieOptions()
    );

    return successResponse(
      res,
      200,
      'Login successful.',
      {
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          createdAt: user.createdAt
        },
        accessToken
      }
    );
  } catch (error) {
    next(error);
  }
};

export const refresh = async (req, res, next) => {
  try {
    const rawToken = req.cookies?.[AUTH_CONSTANTS.REFRESH_COOKIE_NAME];
    if (!rawToken) {
      return errorResponse(res, 401, 'Refresh token is missing.');
    }

    let decoded;
    try {
      decoded = verifyRefreshToken(rawToken);
    } catch {
      return errorResponse(res, 401, 'Invalid or expired refresh token.');
    }

    const user = await User.findById(decoded.sub);
    if (!user) {
      return errorResponse(res, 401, 'User account associated with refresh token no longer exists.');
    }

    const newAccessToken = generateAccessToken(user._id.toString(), user.email);
    const newRefreshToken = generateRefreshToken(user._id.toString());

    res.cookie(
      AUTH_CONSTANTS.REFRESH_COOKIE_NAME,
      newRefreshToken,
      getRefreshTokenCookieOptions()
    );

    return successResponse(
      res,
      200,
      'Token refreshed successfully.',
      {
        accessToken: newAccessToken,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          createdAt: user.createdAt
        }
      }
    );
  } catch (error) {
    next(error);
  }
};

export const logout = async (req, res, next) => {
  try {
    const isProd = process.env.NODE_ENV === 'production';
    res.clearCookie(AUTH_CONSTANTS.REFRESH_COOKIE_NAME, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
      path: '/'
    });

    return successResponse(res, 200, 'Logged out successfully.');
  } catch (error) {
    next(error);
  }
};

export const getMe = async (req, res, next) => {
  try {
    return successResponse(res, 200, 'User profile retrieved.', {
      user: {
        id: req.user._id,
        name: req.user.name,
        email: req.user.email,
        createdAt: req.user.createdAt
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * POST /api/auth/extension/authorize
 * Authenticated endpoint (requires user Bearer token or active session).
 * Generates a short-lived (60s), single-use authorization code for the requesting extension.
 */
export const authorizeExtension = async (req, res, next) => {
  try {
    const { extensionId, state } = extensionAuthorizeSchema.parse(req.body);

    const authCode = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 60 * 1000; // 60 seconds

    extensionAuthCodes.set(authCode, {
      userId: req.user._id.toString(),
      extensionId,
      state,
      expiresAt
    });

    return successResponse(res, 200, 'Extension authorization code generated successfully.', {
      authCode,
      expiresIn: 60
    });
  } catch (error) {
    next(error);
  }
};

/**
 * POST /api/auth/extension/exchange
 * Unauthenticated endpoint for extension background service worker.
 * Exchanges a valid, single-use authorization code for dedicated extension tokens.
 */
export const exchangeExtensionCode = async (req, res, next) => {
  try {
    const { authCode, extensionId, state } = extensionExchangeSchema.parse(req.body);

    const record = extensionAuthCodes.get(authCode);
    if (!record) {
      return errorResponse(res, 401, 'Invalid or expired authorization code.');
    }

    // Always delete code immediately on first attempt (single-use enforcement)
    extensionAuthCodes.delete(authCode);

    if (Date.now() > record.expiresAt) {
      return errorResponse(res, 401, 'Authorization code has expired. Please sign in again.');
    }

    if (record.extensionId !== extensionId || record.state !== state) {
      return errorResponse(res, 403, 'Extension authentication challenge mismatch.');
    }

    const user = await User.findById(record.userId);
    if (!user) {
      return errorResponse(res, 401, 'User account associated with authorization code no longer exists.');
    }

    const accessToken = generateAccessToken(user._id.toString(), user.email);
    const refreshToken = generateRefreshToken(user._id.toString());

    return successResponse(res, 200, 'Extension authentication completed successfully.', {
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * POST /api/auth/extension/refresh
 * Refreshes an expired extension access token using the extension's refresh token.
 */
export const refreshExtensionToken = async (req, res, next) => {
  try {
    const { refreshToken } = extensionRefreshSchema.parse(req.body);

    let decoded;
    try {
      decoded = verifyRefreshToken(refreshToken);
    } catch {
      return errorResponse(res, 401, 'Invalid or expired refresh token. Please sign in again.');
    }

    const user = await User.findById(decoded.sub);
    if (!user) {
      return errorResponse(res, 401, 'User account associated with refresh token no longer exists.');
    }

    const newAccessToken = generateAccessToken(user._id.toString(), user.email);
    const newRefreshToken = generateRefreshToken(user._id.toString());

    return successResponse(res, 200, 'Extension token refreshed successfully.', {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * POST /api/auth/extension/logout
 * Terminates the extension session.
 */
export const logoutExtension = async (req, res, next) => {
  try {
    return successResponse(res, 200, 'Extension session logged out successfully.');
  } catch (error) {
    next(error);
  }
};

