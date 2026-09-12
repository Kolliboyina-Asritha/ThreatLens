import { z } from 'zod';
import { PROTECTION_MODES, USER_DECISIONS } from '../config/constants.js';

export const evaluateProtectionSchema = z.object({
  url: z
    .string({ required_error: 'Target URL is required.' })
    .trim()
    .min(1, 'Target URL cannot be empty.')
    .max(2048, 'URL exceeds maximum length of 2048 characters.'),
  recordAudit: z.boolean().optional().default(true)
});

export const updatePolicySchema = z
  .object({
    mode: z
      .enum(Object.values(PROTECTION_MODES), {
        errorMap: () => ({ message: 'Invalid protection mode. Must be ASK_ME, BALANCED, STRICT, or CUSTOM.' })
      })
      .optional(),
    customThresholds: z
      .object({
        allowMax: z.number().int().min(0).max(99, 'allowMax must be between 0 and 99'),
        warnMax: z.number().int().min(1).max(100, 'warnMax must be between 1 and 100')
      })
      .optional()
  })
  .refine(
    (data) => {
      if (data.customThresholds) {
        return data.customThresholds.allowMax < data.customThresholds.warnMax;
      }
      return true;
    },
    {
      message: 'allowMax threshold must be strictly less than warnMax threshold',
      path: ['customThresholds']
    }
  );

export const addListEntrySchema = z.object({
  value: z
    .string({ required_error: 'Value is required.' })
    .trim()
    .min(1, 'Value cannot be empty.')
    .max(500, 'Value exceeds maximum length.'),
  type: z
    .enum(['DOMAIN', 'URL'], {
      errorMap: () => ({ message: 'Type must be DOMAIN or URL.' })
    })
    .default('DOMAIN')
});

export const recordOverrideSchema = z.object({
  url: z
    .string({ required_error: 'Target URL is required.' })
    .trim()
    .min(1, 'Target URL cannot be empty.'),
  userDecision: z
    .enum(Object.values(USER_DECISIONS), {
      errorMap: () => ({ message: 'Invalid user decision value.' })
    })
    .default(USER_DECISIONS.OVERRIDE),
  reason: z.string().trim().max(500).optional()
});
