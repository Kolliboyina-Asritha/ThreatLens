import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import { AUTH_CONSTANTS } from '../config/constants.js';

/**
 * Generates short-lived Access Token
 * @param {string} userId
 * @param {string} email
 * @returns {string} JWT access token
 */
export const generateAccessToken = (userId, email) => {
  return jwt.sign(
    { sub: userId, email },
    env.JWT_ACCESS_SECRET,
    { expiresIn: AUTH_CONSTANTS.ACCESS_TOKEN_EXPIRY }
  );
};

/**
 * Generates long-lived Refresh Token
 * @param {string} userId
 * @returns {string} JWT refresh token
 */
export const generateRefreshToken = (userId) => {
  return jwt.sign(
    { sub: userId },
    env.JWT_REFRESH_SECRET,
    { expiresIn: AUTH_CONSTANTS.REFRESH_TOKEN_EXPIRY }
  );
};

/**
 * Verifies an Access Token
 * @param {string} token
 * @returns {object} Decoded payload
 */
export const verifyAccessToken = (token) => {
  return jwt.verify(token, env.JWT_ACCESS_SECRET);
};

/**
 * Verifies a Refresh Token
 * @param {string} token
 * @returns {object} Decoded payload
 */
export const verifyRefreshToken = (token) => {
  return jwt.verify(token, env.JWT_REFRESH_SECRET);
};

/**
 * Returns security-hardened Cookie Options for Refresh Token
 * @returns {object} Express cookie options
 */
export const getRefreshTokenCookieOptions = () => {
  const isProd = env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'strict' : 'lax',
    maxAge: AUTH_CONSTANTS.REFRESH_COOKIE_MAX_AGE,
    path: '/'
  };
};
