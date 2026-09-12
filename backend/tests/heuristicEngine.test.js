import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractUrlFeatures } from '../src/services/urlAnalyzer.js';
import { evaluateHeuristics } from '../src/services/heuristicEngine.js';

describe('Heuristic Detection Engine', () => {
  it('returns 0 indicators for a benign HTTPS URL', () => {
    const features = extractUrlFeatures('https://www.google.com');
    const indicators = evaluateHeuristics(features);
    assert.strictEqual(indicators.length, 0);
  });

  it('triggers NO_HTTPS indicator for plain HTTP URL', () => {
    const features = extractUrlFeatures('http://example.com');
    const indicators = evaluateHeuristics(features);
    const noHttps = indicators.find((i) => i.type === 'NO_HTTPS');
    assert.ok(noHttps, 'Should trigger NO_HTTPS');
    assert.strictEqual(noHttps.severity, 'MEDIUM');
    assert.strictEqual(noHttps.score > 0, true);
  });

  it('triggers IP_ADDRESS_HOSTNAME indicator for direct IP URL', () => {
    const features = extractUrlFeatures('http://185.10.20.30/login');
    const indicators = evaluateHeuristics(features);
    const ipInd = indicators.find((i) => i.type === 'IP_ADDRESS_HOSTNAME');
    assert.ok(ipInd, 'Should trigger IP_ADDRESS_HOSTNAME');
    assert.strictEqual(ipInd.severity, 'HIGH');
    assert.strictEqual(ipInd.score >= 20, true);
  });

  it('triggers SUSPICIOUS_KEYWORDS indicator when keywords are found', () => {
    const features = extractUrlFeatures('https://example.com/login/verify-account');
    const indicators = evaluateHeuristics(features);
    const kwInd = indicators.find((i) => i.type === 'SUSPICIOUS_KEYWORDS');
    assert.ok(kwInd, 'Should trigger SUSPICIOUS_KEYWORDS');
    assert.ok(kwInd.details.keywords.includes('login'));
    assert.ok(kwInd.details.keywords.includes('verify'));
    assert.ok(kwInd.details.keywords.includes('account'));
  });

  it('triggers EXCESSIVE_SUBDOMAINS indicator for deep subdomains', () => {
    const features = extractUrlFeatures('https://a.b.c.d.example.com');
    const indicators = evaluateHeuristics(features);
    const subInd = indicators.find((i) => i.type === 'EXCESSIVE_SUBDOMAINS');
    assert.ok(subInd, 'Should trigger EXCESSIVE_SUBDOMAINS');
    assert.strictEqual(subInd.details.subdomainCount, 4);
  });

  it('triggers SUSPICIOUS_PERCENT_ENCODING indicator when encoding is dense', () => {
    const features = extractUrlFeatures('https://example.com/%20%2F%3F%23%25test');
    const indicators = evaluateHeuristics(features);
    const encInd = indicators.find((i) => i.type === 'SUSPICIOUS_PERCENT_ENCODING');
    assert.ok(encInd, 'Should trigger SUSPICIOUS_PERCENT_ENCODING');
  });

  it('triggers EMBEDDED_AT_SYMBOL when "@" is present in URL', () => {
    const features = extractUrlFeatures('https://google.com@attacker.com/login');
    const indicators = evaluateHeuristics(features);
    const atInd = indicators.find((i) => i.type === 'EMBEDDED_AT_SYMBOL');
    assert.ok(atInd, 'Should trigger EMBEDDED_AT_SYMBOL');
    assert.strictEqual(atInd.severity, 'HIGH');
  });
});
