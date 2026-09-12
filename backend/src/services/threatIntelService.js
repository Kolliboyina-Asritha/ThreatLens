import crypto from 'crypto';
import { env } from '../config/env.js';
import { SERVICE_CONFIG } from '../config/constants.js';
import { ThreatIntelCache } from '../models/ThreatIntelCache.js';

/**
 * Computes a deterministic SHA-256 hash of the normalized URL for caching and lookup.
 * @param {string} url - Normalized URL string
 * @returns {string} Hexadecimal SHA-256 hash
 */
export const hashUrl = (url) => {
  return crypto.createHash('sha256').update(url.trim().toLowerCase()).digest('hex');
};

/**
 * Computes VirusTotal URL identifier (base64 of URL without padding '=' per VT v3 spec).
 * @param {string} url - Target URL
 * @returns {string} Base64 URL identifier
 */
export const getVirusTotalUrlId = (url) => {
  return Buffer.from(url.trim()).toString('base64').replace(/=/g, '');
};

/**
 * Normalizes VirusTotal engine detection metrics into an explicit bounded score (0–100).
 * 
 * Formula:
 * - If malicious >= 3: 100 (Immediate High Risk consensus)
 * - Otherwise: min(100, (malicious * 20) + (suspicious * 10))
 * 
 * @param {number} malicious
 * @param {number} suspicious
 * @returns {number} Normalized score 0-100
 */
export const normalizeThreatIntelScore = (malicious = 0, suspicious = 0) => {
  if (malicious >= 3) return 100;
  const raw = malicious * 20 + suspicious * 10;
  return Math.min(100, Math.max(0, Math.round(raw)));
};

/**
 * Retrieves external threat intelligence from VirusTotal with MongoDB caching and graceful degradation.
 * 
 * Security & Privacy Guarantees:
 * 1. Zero Outbound SSRF: Never visits or connects to the submitted target URL.
 * 2. Key Privacy: VirusTotal API key is stored strictly on the backend and never exposed in responses or errors.
 * 3. Cache Resilience: Fresh lookups are cached in MongoDB for 24 hours to preserve API quotas and reduce latency.
 * 
 * @param {string} normalizedUrl - Normalized target URL
 * @returns {Promise<object>} Standardized Threat Intelligence Payload
 */
export const getThreatIntelligence = async (normalizedUrl) => {
  if (!normalizedUrl || typeof normalizedUrl !== 'string') {
    return { available: false, error: 'Invalid URL supplied for threat intelligence.' };
  }

  const urlHash = hashUrl(normalizedUrl);

  // 1. Check MongoDB Cache
  try {
    const cachedRecord = await ThreatIntelCache.findOne({
      urlHash,
      expiresAt: { $gt: new Date() }
    }).lean();

    if (cachedRecord && cachedRecord.result) {
      return {
        ...cachedRecord.result,
        cached: true,
        fetchedAt: cachedRecord.fetchedAt
      };
    }
  } catch (cacheErr) {
    console.warn(`[ThreatIntel] Cache lookup error: ${cacheErr.message}. Continuing with live query.`);
  }

  // 2. Check if VirusTotal API Key is configured
  if (!env.VIRUSTOTAL_API_KEY || env.VIRUSTOTAL_API_KEY.trim() === '') {
    return {
      available: false,
      source: 'VirusTotal',
      cached: false,
      error: 'VirusTotal API key is not configured in backend environment.'
    };
  }

  // 3. Query VirusTotal v3 URL Endpoint safely
  const vtUrlId = getVirusTotalUrlId(normalizedUrl);
  const vtEndpoint = `${env.VIRUSTOTAL_BASE_URL.replace(/\/$/, '')}/urls/${vtUrlId}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), SERVICE_CONFIG.VIRUSTOTAL_TIMEOUT_MS);

  try {
    const response = await fetch(vtEndpoint, {
      method: 'GET',
      headers: {
        'x-apikey': env.VIRUSTOTAL_API_KEY,
        'Accept': 'application/json'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (response.status === 404) {
      // URL has not been analyzed by VirusTotal yet -> Clean / Undetected baseline
      const notFoundResult = {
        available: true,
        source: 'VirusTotal',
        cached: false,
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        reputation: 0,
        score: 0,
        status: 'unseen_by_virustotal'
      };

      // Cache the result
      try {
        await ThreatIntelCache.findOneAndUpdate(
          { urlHash },
          {
            urlHash,
            normalizedUrl,
            provider: 'VirusTotal',
            result: notFoundResult,
            fetchedAt: new Date(),
            expiresAt: ThreatIntelCache.calculateExpiry()
          },
          { upsert: true, new: true }
        );
      } catch (err) {
        // Non-blocking cache write failure
      }

      return notFoundResult;
    }

    if (!response.ok) {
      const isRateLimit = response.status === 429;
      const statusMsg = isRateLimit ? 'VirusTotal API rate limit reached' : `VirusTotal returned status ${response.status}`;
      console.warn(`[ThreatIntel] ${statusMsg}`);
      return {
        available: false,
        source: 'VirusTotal',
        cached: false,
        error: statusMsg
      };
    }

    const vtData = await response.json();
    const stats = vtData?.data?.attributes?.last_analysis_stats || {};
    const reputation = vtData?.data?.attributes?.reputation || 0;

    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);
    const score = normalizeThreatIntelScore(malicious, suspicious);

    const intelResult = {
      available: true,
      source: 'VirusTotal',
      cached: false,
      malicious,
      suspicious,
      harmless,
      undetected,
      reputation,
      score,
      lastAnalysisDate: vtData?.data?.attributes?.last_analysis_date
        ? new Date(vtData.data.attributes.last_analysis_date * 1000)
        : new Date()
    };

    // 4. Persist to Cache
    try {
      await ThreatIntelCache.findOneAndUpdate(
        { urlHash },
        {
          urlHash,
          normalizedUrl,
          provider: 'VirusTotal',
          result: intelResult,
          fetchedAt: new Date(),
          expiresAt: ThreatIntelCache.calculateExpiry()
        },
        { upsert: true, new: true }
      );
    } catch (saveErr) {
      console.warn(`[ThreatIntel] Cache store error: ${saveErr.message}`);
    }

    return intelResult;
  } catch (error) {
    clearTimeout(timeoutId);
    const isTimeout = error.name === 'AbortError';
    const message = isTimeout
      ? `VirusTotal request timed out after ${SERVICE_CONFIG.VIRUSTOTAL_TIMEOUT_MS}ms`
      : `VirusTotal API error (${error.message})`;

    console.warn(`[ThreatIntel] Notice: ${message}. Degrading gracefully.`);
    return {
      available: false,
      source: 'VirusTotal',
      cached: false,
      error: message
    };
  }
};
