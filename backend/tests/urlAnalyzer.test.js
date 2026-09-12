import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractUrlFeatures, findSuspiciousKeywords } from '../src/services/urlAnalyzer.js';
import { normalizeUrl, URLNormalizationError } from '../src/services/urlNormalizer.js';

describe('URL Normalization & Validation', () => {
  it('normalizes a standard HTTPS URL correctly', () => {
    const res = normalizeUrl('  https://www.Google.com/search?q=cybersecurity#top  ');
    assert.strictEqual(res.normalizedUrl, 'https://www.google.com/search?q=cybersecurity#top');
    assert.strictEqual(res.originalUrl, 'https://www.Google.com/search?q=cybersecurity#top');
  });

  it('prepends http:// to URLs missing scheme', () => {
    const res = normalizeUrl('example.com/test');
    assert.strictEqual(res.normalizedUrl, 'http://example.com/test');
  });

  it('rejects unsupported hazardous protocols like javascript:', () => {
    assert.throws(
      () => normalizeUrl('javascript:alert(1)'),
      (err) => err instanceof URLNormalizationError && err.code === 'UNSUPPORTED_PROTOCOL'
    );
  });

  it('rejects unsupported protocols like file:', () => {
    assert.throws(
      () => normalizeUrl('file:///etc/passwd'),
      (err) => err instanceof URLNormalizationError && err.code === 'UNSUPPORTED_PROTOCOL'
    );
  });

  it('rejects empty or whitespace-only URLs', () => {
    assert.throws(
      () => normalizeUrl('   '),
      (err) => err instanceof URLNormalizationError && err.code === 'EMPTY_URL'
    );
  });
});

describe('URL Feature Extraction', () => {
  it('extracts features for safe-looking HTTPS URL', () => {
    const features = extractUrlFeatures('https://www.google.com');
    assert.strictEqual(features.protocol, 'https');
    assert.strictEqual(features.usesHttps, true);
    assert.strictEqual(features.usesHttp, false);
    assert.strictEqual(features.isIpAddress, false);
    assert.strictEqual(features.hostname, 'www.google.com');
    assert.strictEqual(features.containsSuspiciousKeyword, false);
  });

  it('extracts features for HTTP plain URL', () => {
    const features = extractUrlFeatures('http://example.com');
    assert.strictEqual(features.protocol, 'http');
    assert.strictEqual(features.usesHttps, false);
    assert.strictEqual(features.usesHttp, true);
    assert.strictEqual(features.isIpAddress, false);
  });

  it('detects IPv4 hostname accurately', () => {
    const features = extractUrlFeatures('http://185.10.20.30/login');
    assert.strictEqual(features.isIpAddress, true);
    assert.strictEqual(features.isIpv4, true);
    assert.strictEqual(features.hostname, '185.10.20.30');
    assert.strictEqual(features.containsSuspiciousKeyword, true);
    assert.ok(features.detectedKeywords.includes('login'));
  });

  it('detects multiple subdomains accurately', () => {
    const features = extractUrlFeatures('https://login.verify.account.example.com');
    assert.strictEqual(features.subdomainCount, 3);
    assert.strictEqual(features.containsExcessiveSubdomains, true);
    assert.deepStrictEqual(features.subdomains, ['login', 'verify', 'account']);
  });

  it('extracts percent-encoded sequences', () => {
    const features = extractUrlFeatures('https://example.com/%20%2F%3F%23%25test');
    assert.strictEqual(features.percentCount >= 5, true);
    assert.strictEqual(features.containsEncodedCharacters, true);
  });

  it('identifies long URLs with excessive length', () => {
    const longPath = 'a'.repeat(90);
    const features = extractUrlFeatures(`https://example.com/${longPath}?param1=123&param2=456`);
    assert.strictEqual(features.containsExcessiveLength, true);
    assert.strictEqual(features.urlLength > 80, true);
  });

  it('extracts suspicious security keywords from paths', () => {
    const detected = findSuspiciousKeywords('https://test.com/banking/update-password-confirm');
    assert.ok(detected.includes('banking'));
    assert.ok(detected.includes('update'));
    assert.ok(detected.includes('password'));
    assert.ok(detected.includes('confirm'));
  });
});
