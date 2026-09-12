process.env.NODE_ENV = 'test';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import {
  hashUrl,
  getVirusTotalUrlId,
  normalizeThreatIntelScore,
  getThreatIntelligence
} from '../src/services/threatIntelService.js';
import { ThreatIntelCache } from '../src/models/ThreatIntelCache.js';
import { env } from '../src/config/env.js';

describe('Phase 2 - Threat Intelligence Service Unit & Caching Tests', () => {
  before(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(env.MONGODB_URI, { family: 4, serverSelectionTimeoutMS: 5000 });
    }
    await ThreatIntelCache.deleteMany({ normalizedUrl: { $regex: /test-ti/ } });
  });

  after(async () => {
    await ThreatIntelCache.deleteMany({ normalizedUrl: { $regex: /test-ti/ } });
    await mongoose.disconnect();
  });

  it('hashes normalized URLs deterministically via SHA-256', () => {
    const hash1 = hashUrl('https://example.com/login');
    const hash2 = hashUrl('  https://Example.Com/login  ');
    assert.strictEqual(hash1, hash2);
    assert.strictEqual(hash1.length, 64);
  });

  it('generates compliant base64 VirusTotal URL identifiers without padding', () => {
    const vtId = getVirusTotalUrlId('https://example.com');
    assert.ok(typeof vtId === 'string');
    assert.ok(!vtId.includes('='));
  });

  it('normalizes threat intelligence score correctly per formula', () => {
    // 0 detections -> 0
    assert.strictEqual(normalizeThreatIntelScore(0, 0), 0);
    // 1 malicious -> 20
    assert.strictEqual(normalizeThreatIntelScore(1, 0), 20);
    // 1 malicious + 2 suspicious -> 20 + 20 = 40
    assert.strictEqual(normalizeThreatIntelScore(1, 2), 40);
    // >= 3 malicious -> 100
    assert.strictEqual(normalizeThreatIntelScore(3, 0), 100);
    assert.strictEqual(normalizeThreatIntelScore(10, 5), 100);
  });

  it('retrieves from MongoDB cache when fresh entry exists', async () => {
    const testUrl = 'https://test-ti-cache-hit.org/portal';
    const urlHash = hashUrl(testUrl);

    // Seed cache
    await ThreatIntelCache.create({
      urlHash,
      normalizedUrl: testUrl,
      provider: 'VirusTotal',
      result: {
        available: true,
        source: 'VirusTotal',
        malicious: 2,
        suspicious: 1,
        harmless: 50,
        undetected: 10,
        reputation: -15,
        score: 50
      },
      fetchedAt: new Date(),
      expiresAt: ThreatIntelCache.calculateExpiry()
    });

    const intel = await getThreatIntelligence(testUrl);
    assert.strictEqual(intel.available, true);
    assert.strictEqual(intel.cached, true);
    assert.strictEqual(intel.malicious, 2);
    assert.strictEqual(intel.score, 50);
  });

  it('degrades gracefully when VirusTotal API key is unconfigured', async () => {
    const originalKey = env.VIRUSTOTAL_API_KEY;
    env.VIRUSTOTAL_API_KEY = '';

    const intel = await getThreatIntelligence('https://test-ti-unconfigured.org');
    assert.strictEqual(intel.available, false);
    assert.strictEqual(intel.source, 'VirusTotal');
    assert.ok(intel.error);

    env.VIRUSTOTAL_API_KEY = originalKey;
  });
});
