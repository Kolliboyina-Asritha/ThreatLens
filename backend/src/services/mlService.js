import { env } from '../config/env.js';
import { ML_FEATURE_SCHEMA_VERSION, SERVICE_CONFIG } from '../config/constants.js';

/**
 * Transforms normalized features from urlAnalyzer into the exact 18-element ML contract schema.
 * @param {object} features - Extracted URL features
 * @returns {object} Canonical 18-feature payload
 */
export const transformFeaturesForML = (features) => {
  return {
    url_length: Number(features.urlLength || 0),
    hostname_length: Number(features.hostnameLength || 0),
    path_length: Number(features.pathnameLength || 0),
    query_length: Number(features.queryLength || 0),
    dot_count: Number(features.dotCount || 0),
    subdomain_count: Number(features.subdomainCount || 0),
    path_segment_count: Number(features.pathSegmentCount || 0),
    query_params_count: Number(features.queryParamsCount || 0),
    special_char_count: Number(features.specialCharacterCount || 0),
    digits_count: Number(features.digitsCount || 0),
    hyphen_count: Number(features.hyphenCount || 0),
    underscore_count: Number(features.underscoreCount || 0),
    at_symbol_count: Number(features.atSymbolCount || 0),
    percent_count: Number(features.percentCount || 0),
    uses_https: features.usesHttps ? 1 : 0,
    is_ip_address: features.isIpAddress ? 1 : 0,
    suspicious_keyword_count: Number(features.detectedKeywords ? features.detectedKeywords.length : 0),
    suspicious_hostname_pattern: features.containsSuspiciousHostnamePattern ? 1 : 0
  };
};

/**
 * Evaluates URL threat probability using the Python FastAPI Random Forest ML Service.
 * Fails safely and gracefully without blocking the scanner if ML service is unreachable.
 * 
 * @param {object} features - Extracted features from urlAnalyzer
 * @returns {Promise<{ available: boolean, prediction: string, probability: number|null, modelVersion?: string, topContributingFeatures?: Array, error?: string }>}
 */
export const predictThreatWithML = async (features) => {
  const mlPayload = {
    features: transformFeaturesForML(features)
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), SERVICE_CONFIG.ML_TIMEOUT_MS);

  try {
    const baseUrl = process.env.ML_SERVICE_URL || env.ML_SERVICE_URL || 'http://localhost:8000';
    const url = `${baseUrl.replace(/\/$/, '')}/predict`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify(mlPayload),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown ML service error');
      console.warn(`[ML Service] Warning: Server responded with status ${response.status}: ${errorText}`);
      return {
        available: false,
        prediction: 'unavailable',
        probability: null,
        error: `ML service returned HTTP ${response.status}`
      };
    }

    const data = await response.json();
    return {
      available: true,
      prediction: data.prediction || 'unknown',
      probability: typeof data.probability === 'number' ? data.probability : 0,
      modelVersion: data.model_version || '1.0.0',
      schemaVersion: data.schema_version || ML_FEATURE_SCHEMA_VERSION,
      topContributingFeatures: data.top_contributing_features || []
    };
  } catch (error) {
    clearTimeout(timeoutId);
    const isTimeout = error.name === 'AbortError';
    const message = isTimeout
      ? `ML service request timed out after ${SERVICE_CONFIG.ML_TIMEOUT_MS}ms`
      : `ML service unreachable (${error.message})`;

    console.warn(`[ML Service] Notice: ML classification unavailable (${message}). Degrading gracefully.`);
    return {
      available: false,
      prediction: 'unavailable',
      probability: null,
      error: message
    };
  }
};
