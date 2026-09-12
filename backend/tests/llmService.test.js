process.env.NODE_ENV = 'test';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateFallbackExplanation,
  explainThreatEvidence
} from '../src/services/llmService.js';
import { env } from '../src/config/env.js';

describe('Phase 2 - LLM Explanation Layer Unit & Fallback Tests', () => {
  const sampleEvidenceHigh = {
    url: 'http://185.10.20.30/login/verify-account',
    riskScore: 85,
    riskLevel: 'HIGH_RISK',
    indicators: [
      { message: 'The hostname is an IP address rather than a domain name.' },
      { message: 'The URL does not use HTTPS.' }
    ],
    ml: {
      available: true,
      probability: 0.94
    },
    threatIntelligence: {
      available: true,
      malicious: 4
    }
  };

  const sampleEvidenceSafe = {
    url: 'https://www.google.com',
    riskScore: 5,
    riskLevel: 'SAFE',
    indicators: [],
    ml: {
      available: true,
      probability: 0.02
    },
    threatIntelligence: {
      available: true,
      malicious: 0
    }
  };

  it('generates high-quality fallback explanation for HIGH_RISK evidence', () => {
    const explanation = generateFallbackExplanation(sampleEvidenceHigh);

    assert.ok(typeof explanation.summary === 'string');
    assert.ok(explanation.summary.includes('85/100'));
    assert.ok(Array.isArray(explanation.whyRisky));
    assert.ok(explanation.whyRisky.length >= 2);
    assert.ok(Array.isArray(explanation.recommendations));
    assert.ok(explanation.recommendations.some(r => r.includes('NOT click')));
    assert.strictEqual(typeof explanation.confidenceNote, 'string');
  });

  it('generates clear fallback explanation for SAFE evidence', () => {
    const explanation = generateFallbackExplanation(sampleEvidenceSafe);

    assert.ok(typeof explanation.summary === 'string');
    assert.ok(explanation.summary.includes('5/100'));
    assert.ok(Array.isArray(explanation.whyRisky));
    assert.ok(Array.isArray(explanation.recommendations));
  });

  it('degrades seamlessly to fallback explanation when LLM API key is empty', async () => {
    const originalKey = env.LLM_API_KEY;
    env.LLM_API_KEY = '';

    const explanation = await explainThreatEvidence(sampleEvidenceHigh);
    assert.ok(explanation.summary);
    assert.ok(explanation.whyRisky.length > 0);
    assert.ok(explanation.recommendations.length > 0);

    env.LLM_API_KEY = originalKey;
  });
});
