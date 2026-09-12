import { z } from 'zod';

const DANGEROUS_SCHEMES = ['javascript:', 'file:', 'data:', 'ftp:', 'vbscript:', 'about:', 'blob:'];

export const scanUrlSchema = z.object({
  url: z
    .string()
    .trim()
    .min(1, 'URL is required')
    .max(2048, 'URL length exceeds maximum limit of 2048 characters')
    .refine((val) => {
      const lower = val.toLowerCase().trim();
      return !DANGEROUS_SCHEMES.some((scheme) => lower.startsWith(scheme));
    }, {
      message: 'Unsupported or unsafe URL protocol. Only HTTP and HTTPS are permitted.'
    })
    .refine((val) => {
      try {
        let testUrl = val;
        if (!/^https?:\/\//i.test(testUrl)) {
          testUrl = `http://${testUrl}`;
        }
        const parsed = new URL(testUrl);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
      } catch {
        return false;
      }
    }, {
      message: 'Invalid URL syntax.'
    })
});

export const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(10)
});
