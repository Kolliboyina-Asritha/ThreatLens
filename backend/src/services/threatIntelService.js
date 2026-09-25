import crypto from 'crypto';
import { env } from '../config/env.js';
import { SERVICE_CONFIG } from '../config/constants.js';
import { ThreatIntelCache } from '../models/ThreatIntelCache.js';

/**
 * Computes a deterministic SHA-256 hash of the normalized URL
 * for MongoDB caching and lookup.
 */
export const hashUrl = (url) => {
  return crypto
    .createHash('sha256')
    .update(url.trim().toLowerCase())
    .digest('hex');
};

/**
 * Computes the VirusTotal v3 URL identifier.
 *
 * VirusTotal expects the URL encoded using URL-safe Base64
 * with "=" padding removed.
 */
export const getVirusTotalUrlId = (url) => {
  return Buffer.from(url.trim())
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
};

/**
 * Converts VirusTotal detection counts into a bounded
 * 0-100 Threat Intelligence score.
 *
 * Formula:
 * malicious >= 3 -> 100
 * otherwise:
 * malicious * 20 + suspicious * 10
 */
export const normalizeThreatIntelScore = (
  malicious = 0,
  suspicious = 0
) => {
  const maliciousCount = Number(malicious) || 0;
  const suspiciousCount = Number(suspicious) || 0;

  if (maliciousCount >= 3) {
    return 100;
  }

  const raw =
    maliciousCount * 20 +
    suspiciousCount * 10;

  return Math.min(
    100,
    Math.max(0, Math.round(raw))
  );
};

/**
 * Retrieves external threat intelligence from VirusTotal.
 *
 * Important:
 * - 404 means VirusTotal has no URL report.
 * - 404 does NOT mean the URL is clean.
 * - Unknown VT reputation is represented using null values.
 * - VirusTotal API failures gracefully disable this engine.
 */
export const getThreatIntelligence = async (normalizedUrl) => {
  if (
    !normalizedUrl ||
    typeof normalizedUrl !== 'string'
  ) {
    return {
      available: false,
      source: 'VirusTotal',
      cached: false,
      status: 'invalid_input',
      error: 'Invalid URL supplied for threat intelligence.'
    };
  }

  const urlHash = hashUrl(normalizedUrl);

  // ============================================================
  // 1. CHECK MONGODB CACHE
  // ============================================================

  try {
    const cachedRecord = await ThreatIntelCache.findOne({
      urlHash,
      expiresAt: { $gt: new Date() }
    }).lean();

    if (cachedRecord?.result) {
      return {
        ...cachedRecord.result,
        cached: true,
        fetchedAt: cachedRecord.fetchedAt
      };
    }
  } catch (cacheErr) {
    console.warn(
      `[ThreatIntel] Cache lookup error: ${cacheErr.message}. Continuing with live query.`
    );
  }

  // ============================================================
  // 2. CHECK VIRUSTOTAL API KEY
  // ============================================================

  if (
    !env.VIRUSTOTAL_API_KEY ||
    env.VIRUSTOTAL_API_KEY.trim() === ''
  ) {
    return {
      available: false,
      source: 'VirusTotal',
      cached: false,
      status: 'unconfigured',
      error:
        'VirusTotal API key is not configured in backend environment.'
    };
  }

  // ============================================================
  // 3. BUILD VIRUSTOTAL URL
  // ============================================================

  const vtUrlId = getVirusTotalUrlId(normalizedUrl);

  const baseUrl =
    env.VIRUSTOTAL_BASE_URL.replace(/\/$/, '');

  const vtEndpoint =
    `${baseUrl}/urls/${vtUrlId}`;

  const controller = new AbortController();

  const timeoutId = setTimeout(
    () => controller.abort(),
    SERVICE_CONFIG.VIRUSTOTAL_TIMEOUT_MS
  );

  try {
    // ==========================================================
    // 4. QUERY VIRUSTOTAL
    // ==========================================================

    const response = await fetch(vtEndpoint, {
      method: 'GET',
      headers: {
        'x-apikey': env.VIRUSTOTAL_API_KEY,
        'Accept': 'application/json'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    // ==========================================================
    // 5. URL NOT FOUND IN VIRUSTOTAL
    // ==========================================================

    if (response.status === 404) {
      console.log(
        `[ThreatIntel] VirusTotal has no existing report for URL hash ${urlHash.slice(0, 12)}...`
      );

      /**
       * IMPORTANT:
       *
       * This is NOT "clean".
       *
       * VirusTotal simply has no existing URL report.
       */
      const unknownResult = {
        available: true,
        source: 'VirusTotal',
        cached: false,

        status: 'unseen_by_virustotal',

        malicious: null,
        suspicious: null,
        harmless: null,
        undetected: null,

        reputation: null,

        // null = no VT score available
        score: null
      };

      // Cache the "unknown" state.
      try {
        await ThreatIntelCache.findOneAndUpdate(
          { urlHash },
          {
            urlHash,
            normalizedUrl,
            provider: 'VirusTotal',
            result: unknownResult,
            fetchedAt: new Date(),
            expiresAt:
              ThreatIntelCache.calculateExpiry()
          },
          {
            upsert: true,
            new: true
          }
        );
      } catch (cacheErr) {
        console.warn(
          `[ThreatIntel] Unknown-result cache error: ${cacheErr.message}`
        );
      }

      return unknownResult;
    }

    // ==========================================================
    // 6. RATE LIMIT
    // ==========================================================

    if (response.status === 429) {
      console.warn(
        '[ThreatIntel] VirusTotal API rate limit reached.'
      );

      return {
        available: false,
        source: 'VirusTotal',
        cached: false,
        status: 'rate_limited',
        error:
          'VirusTotal API rate limit reached.'
      };
    }

    // ==========================================================
    // 7. OTHER API ERRORS
    // ==========================================================

    if (!response.ok) {
      console.warn(
        `[ThreatIntel] VirusTotal returned HTTP ${response.status}`
      );

      return {
        available: false,
        source: 'VirusTotal',
        cached: false,
        status: 'api_error',
        error:
          `VirusTotal returned status ${response.status}`
      };
    }

    // ==========================================================
    // 8. PARSE VIRUSTOTAL RESPONSE
    // ==========================================================

    const vtData = await response.json();

    const attributes =
      vtData?.data?.attributes || {};

    const stats =
      attributes.last_analysis_stats || {};

    // ==========================================================
    // 9. EXTRACT DETECTION COUNTS
    // ==========================================================

    const malicious =
      Number(stats.malicious || 0);

    const suspicious =
      Number(stats.suspicious || 0);

    const harmless =
      Number(stats.harmless || 0);

    const undetected =
      Number(stats.undetected || 0);

    const reputation =
      Number(attributes.reputation || 0);

    const totalEngines =
      malicious +
      suspicious +
      harmless +
      undetected;

    // ==========================================================
    // 10. CALCULATE VT SCORE
    // ==========================================================

    const score =
      normalizeThreatIntelScore(
        malicious,
        suspicious
      );

    console.log(
      `[ThreatIntel] VirusTotal result: malicious=${malicious}, suspicious=${suspicious}, harmless=${harmless}, undetected=${undetected}, score=${score}`
    );

    // ==========================================================
    // 11. BUILD STANDARDIZED RESULT
    // ==========================================================

    const intelResult = {
      available: true,
      source: 'VirusTotal',
      cached: false,

      status: 'analyzed',

      malicious,
      suspicious,
      harmless,
      undetected,

      totalEngines,

      reputation,

      score,

      lastAnalysisDate:
        attributes.last_analysis_date
          ? new Date(
              attributes.last_analysis_date * 1000
            )
          : null
    };

    // ==========================================================
    // 12. SAVE RESULT TO MONGODB CACHE
    // ==========================================================

    try {
      await ThreatIntelCache.findOneAndUpdate(
        { urlHash },
        {
          urlHash,
          normalizedUrl,
          provider: 'VirusTotal',
          result: intelResult,
          fetchedAt: new Date(),
          expiresAt:
            ThreatIntelCache.calculateExpiry()
        },
        {
          upsert: true,
          new: true
        }
      );
    } catch (saveErr) {
      console.warn(
        `[ThreatIntel] Cache store error: ${saveErr.message}`
      );
    }

    return intelResult;

  } catch (error) {
    clearTimeout(timeoutId);

    const isTimeout =
      error.name === 'AbortError';

    const message = isTimeout
      ? `VirusTotal request timed out after ${SERVICE_CONFIG.VIRUSTOTAL_TIMEOUT_MS}ms`
      : `VirusTotal API error (${error.message})`;

    console.warn(
      `[ThreatIntel] ${message}. Degrading gracefully.`
    );

    return {
      available: false,
      source: 'VirusTotal',
      cached: false,
      status: isTimeout
        ? 'timeout'
        : 'request_error',
      error: message
    };
  }
};
