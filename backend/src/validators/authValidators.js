import { z } from 'zod';

export const registerSchema = z.object({
  name: z.string().trim().min(2, 'Name must be at least 2 characters long').max(100, 'Name must not exceed 100 characters'),
  email: z.string().trim().email('Invalid email address format').toLowerCase().max(255, 'Email is too long'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters long')
    .max(128, 'Password must not exceed 128 characters')
    .regex(/[A-Za-z]/, 'Password must contain at least one letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
});

export const loginSchema = z.object({
  email: z.string().trim().email('Invalid email address format').toLowerCase(),
  password: z.string().min(1, 'Password is required')
});

export const extensionAuthorizeSchema = z.object({
  extensionId: z.string().trim().min(1, 'Extension ID is required'),
  state: z.string().trim().min(1, 'State challenge is required')
});

export const extensionExchangeSchema = z.object({
  authCode: z.string().trim().min(1, 'Authorization code is required'),
  extensionId: z.string().trim().min(1, 'Extension ID is required'),
  state: z.string().trim().min(1, 'State challenge is required')
});

export const extensionRefreshSchema = z.object({
  refreshToken: z.string().trim().min(1, 'Refresh token is required'),
  extensionId: z.string().trim().optional()
});

