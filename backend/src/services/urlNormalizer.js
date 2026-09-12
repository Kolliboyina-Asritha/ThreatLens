/**
 * URL Normalization Service
 * Safely parses and normalizes URLs without performing any network requests (SSRF-safe).
 */

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);
const DISALLOWED_PROTOCOLS = new Set(['javascript:', 'file:', 'data:', 'ftp:', 'vbscript:', 'about:', 'blob:']);

export class URLNormalizationError extends Error {
  constructor(message, code = 'INVALID_URL') {
    super(message);
    this.name = 'URLNormalizationError';
    this.code = code;
  }
}

/**
 * Normalizes and validates a given URL string.
 * @param {string} rawUrl - User-provided URL string
 * @returns {{ originalUrl: string, normalizedUrl: string, parsedUrl: URL }}
 */
export const normalizeUrl = (rawUrl) => {
  if (!rawUrl || typeof rawUrl !== 'string') {
    throw new URLNormalizationError('URL must be a non-empty string', 'EMPTY_URL');
  }

  const originalUrl = rawUrl.trim();

  if (originalUrl.length === 0) {
    throw new URLNormalizationError('URL cannot be empty', 'EMPTY_URL');
  }

  if (originalUrl.length > 2048) {
    throw new URLNormalizationError('URL exceeds maximum permitted length of 2048 characters', 'URL_TOO_LONG');
  }

  const lowerRaw = originalUrl.toLowerCase();
  for (const disallowed of DISALLOWED_PROTOCOLS) {
    if (lowerRaw.startsWith(disallowed)) {
      throw new URLNormalizationError(`Protocol "${disallowed}" is unsupported and potentially hazardous`, 'UNSUPPORTED_PROTOCOL');
    }
  }

  let parseTarget = originalUrl;
  // If no scheme is present (e.g. "example.com/path"), prepend "http://"
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(parseTarget)) {
    // If it starts with "//", prepend "http:"
    if (parseTarget.startsWith('//')) {
      parseTarget = `http:${parseTarget}`;
    } else {
      parseTarget = `http://${parseTarget}`;
    }
  }

  let parsed;
  try {
    parsed = new URL(parseTarget);
  } catch (err) {
    throw new URLNormalizationError(`Malformed URL: ${err.message}`, 'MALFORMED_URL');
  }

  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    throw new URLNormalizationError(`Protocol "${parsed.protocol}" is not allowed. Only HTTP and HTTPS are supported.`, 'UNSUPPORTED_PROTOCOL');
  }

  if (!parsed.hostname) {
    throw new URLNormalizationError('URL must contain a valid hostname or IP address', 'MISSING_HOSTNAME');
  }

  // Remove default ports if explicitly provided (80 for http, 443 for https)
  let normalizedPort = parsed.port;
  if ((parsed.protocol === 'http:' && parsed.port === '80') || (parsed.protocol === 'https:' && parsed.port === '443')) {
    normalizedPort = '';
  }

  // Reconstruct clean normalized URL string
  const protocol = parsed.protocol.toLowerCase();
  const hostname = parsed.hostname.toLowerCase();
  const portStr = normalizedPort ? `:${normalizedPort}` : '';
  const pathname = parsed.pathname || '/';
  const search = parsed.search || '';
  const hash = parsed.hash || '';

  const normalizedUrl = `${protocol}//${hostname}${portStr}${pathname}${search}${hash}`;

  return {
    originalUrl,
    normalizedUrl,
    parsedUrl: parsed
  };
};
