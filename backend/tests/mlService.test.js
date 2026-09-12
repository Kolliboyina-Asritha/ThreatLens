process.env.NODE_ENV = 'test';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { transformFeaturesForML, predictThreatWithML } from '../src/services/mlService.js';
import { ML_FEATURE_NAMES } from '../src/config/constants.js';

describe('Phase 2 - Machine Learning Service Unit Tests', () => {
  const sampleFeatures = {
    urlLength: 45,
    hostnameLength: 14,
    pathnameLength: 20,
    queryLength: 10,
    dotCount: 3,
    subdomainCount: 1,
    pathSegmentCount: 2,
    queryParamsCount: 1,
    specialCharacterCount: 5,
    digitsCount: 8,
    hyphenCount: 2,
    underscoreCount: 1,
    atSymbolCount: 0,
    percentCount: 0,
    usesHttps: true,
    isIpAddress: false,
    detectedKeywords: ['login', 'verify'],
    containsSuspiciousHostnamePattern: true
  };

  it('transforms Node.js URL features into the exact 18-element contract schema', () => {
    const transformed = transformFeaturesForML(sampleFeatures);

    assert.strictEqual(Object.keys(transformed).length, 18);
    for (const key of ML_FEATURE_NAMES) {
      assert.ok(key in transformed, `Expected key "${key}" in ML feature dictionary`);
      assert.strictEqual(typeof transformed[key], 'number', `Key "${key}" should be numeric`);
    }

    assert.strictEqual(transformed.uses_https, 1);
    assert.strictEqual(transformed.is_ip_address, 0);
    assert.strictEqual(transformed.suspicious_keyword_count, 2);
    assert.strictEqual(transformed.suspicious_hostname_pattern, 1);
  });

  it('handles empty or missing optional features safely', () => {
    const minimalFeatures = {
      usesHttps: false,
      isIpAddress: true
    };

    const transformed = transformFeaturesForML(minimalFeatures);
    assert.strictEqual(transformed.url_length, 0);
    assert.strictEqual(transformed.uses_https, 0);
    assert.strictEqual(transformed.is_ip_address, 1);
    assert.strictEqual(transformed.suspicious_keyword_count, 0);
  });

  it('degrades gracefully when ML service is offline', async () => {
    // Port 59999 has no running service
    process.env.ML_SERVICE_URL = 'http://127.0.0.1:59999';
    const result = await predictThreatWithML(sampleFeatures);

    assert.strictEqual(result.available, false);
    assert.strictEqual(result.prediction, 'unavailable');
    assert.strictEqual(result.probability, null);
    assert.ok(result.error);
  });
});
