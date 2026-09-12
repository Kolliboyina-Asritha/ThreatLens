process.env.NODE_ENV = 'test';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import mongoose from 'mongoose';
import { createApp } from '../src/app.js';
import { User } from '../src/models/User.js';
import { Scan } from '../src/models/Scan.js';
import { env } from '../src/config/env.js';

const app = createApp();

describe('Phase 2 - Multi-Engine URL Threat Scanner Integration Tests', () => {
  let token = '';

  before(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(env.MONGODB_URI, { family: 4, serverSelectionTimeoutMS: 5000 });
    }
    await User.deleteMany({ email: { $regex: /@phase2test\.io$/ } });
    await Scan.deleteMany({});

    const registerRes = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Phase2 Tester',
        email: `p2_${Date.now()}@phase2test.io`,
        password: 'Password123!'
      });

    token = registerRes.body.data.accessToken;
  });

  after(async () => {
    await User.deleteMany({ email: { $regex: /@phase2test\.io$/ } });
    await Scan.deleteMany({});
    await mongoose.disconnect();
  });

  it('POST /api/scan/url - returns complete Phase 2 intelligence payload', async () => {
    const res = await request(app)
      .post('/api/scan/url')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.google.com' });

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.success, true);
    const data = res.body.data;

    // Verify Phase 1 fields
    assert.ok(data.scanId);
    assert.strictEqual(typeof data.riskScore, 'number');
    assert.ok(['SAFE', 'SUSPICIOUS', 'HIGH_RISK'].includes(data.riskLevel));
    assert.ok(Array.isArray(data.indicators));

    // Verify Phase 2 fields
    assert.ok(data.riskBreakdown);
    assert.ok(data.riskBreakdown.heuristics);
    assert.ok(Array.isArray(data.riskBreakdown.activeEngines));

    assert.ok(data.aiExplanation);
    assert.ok(typeof data.aiExplanation.summary === 'string');
    assert.ok(Array.isArray(data.aiExplanation.whyRisky));
    assert.ok(Array.isArray(data.aiExplanation.recommendations));

    assert.ok(Array.isArray(data.investigationTimeline));
    assert.ok(data.investigationTimeline.some(t => t.stage === 'FEATURE_EXTRACTION'));
    assert.ok(data.investigationTimeline.some(t => t.stage === 'HEURISTIC_ANALYSIS'));
    assert.ok(data.investigationTimeline.some(t => t.stage === 'RISK_FUSION'));

    assert.strictEqual(data.analysisVersion, '2.0.0');
  });

  it('GET /api/scans/:id - retrieves complete Phase 2 scan details', async () => {
    // Create scan first
    const createRes = await request(app)
      .post('/api/scan/url')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'http://185.10.20.30/login/verify-account' });

    const scanId = createRes.body.data.scanId;

    const detailRes = await request(app)
      .get(`/api/scans/${scanId}`)
      .set('Authorization', `Bearer ${token}`);

    assert.strictEqual(detailRes.status, 200);
    const data = detailRes.body.data;
    assert.strictEqual(data.scanId, scanId);
    assert.ok(data.riskBreakdown);
    assert.ok(data.aiExplanation);
    assert.ok(data.investigationTimeline);
  });
});
