process.env.NODE_ENV = 'test';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import mongoose from 'mongoose';
import { createApp } from '../src/app.js';
import { User } from '../src/models/User.js';
import { ProtectionPolicy } from '../src/models/ProtectionPolicy.js';
import { SecurityEvent } from '../src/models/SecurityEvent.js';
import { env } from '../src/config/env.js';

const app = createApp();

describe('Phase 3 - Protection API Endpoints & Multi-Tenant Security Tests', () => {
  let userAToken = '';
  let userBToken = '';
  let userAId = '';
  let userBId = '';

  before(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(env.MONGODB_URI, { family: 4, serverSelectionTimeoutMS: 5000 });
    }
    await ProtectionPolicy.deleteMany({});
    await SecurityEvent.deleteMany({});
    await User.deleteMany({ email: { $regex: /@protapi-test\.io$/ } });

    // Register User A
    const resA = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Alpha User',
        email: `alpha_${Date.now()}@protapi-test.io`,
        password: 'Password123!'
      });
    userAToken = resA.body.data.accessToken;
    userAId = resA.body.data.user.id;

    // Register User B
    const resB = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Beta User',
        email: `beta_${Date.now()}@protapi-test.io`,
        password: 'Password123!'
      });
    userBToken = resB.body.data.accessToken;
    userBId = resB.body.data.user.id;
  });

  after(async () => {
    await ProtectionPolicy.deleteMany({});
    await SecurityEvent.deleteMany({});
    await User.deleteMany({ email: { $regex: /@protapi-test\.io$/ } });
    await mongoose.disconnect();
  });

  it('GET /api/protection/policy - initializes and returns default policy', async () => {
    const res = await request(app)
      .get('/api/protection/policy')
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.mode, 'ASK_ME');
    assert.strictEqual(res.body.data.customThresholds.allowMax, 29);
  });

  it('PUT /api/protection/policy - updates user policy mode and thresholds', async () => {
    const res = await request(app)
      .put('/api/protection/policy')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        mode: 'BALANCED',
        customThresholds: { allowMax: 25, warnMax: 65 }
      });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.mode, 'BALANCED');
    assert.strictEqual(res.body.data.customThresholds.allowMax, 25);
  });

  it('POST /api/protection/evaluate - evaluates URL, applies policy, and logs SecurityEvent', async () => {
    const res = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ url: 'https://www.google.com' });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.recommendation, 'ALLOW');
    assert.strictEqual(res.body.data.action, 'ALLOW');
    assert.ok(res.body.data.eventId);
  });

  it('POST /api/protection/allowlist - adds trusted domain and removes from blocklist', async () => {
    const res = await request(app)
      .post('/api/protection/allowlist')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ value: 'trusted-corp.com', type: 'DOMAIN' });

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.success, true);
    assert.ok(res.body.data.some((item) => item.value === 'trusted-corp.com'));
  });

  it('POST /api/protection/blocklist - adds blocked domain and enforces BLOCK action', async () => {
    const res = await request(app)
      .post('/api/protection/blocklist')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ value: 'forbidden-site.com', type: 'DOMAIN' });

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.success, true);

    // Evaluate blocked URL
    const evalRes = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ url: 'https://forbidden-site.com/subpath' });

    assert.strictEqual(evalRes.status, 200);
    assert.strictEqual(evalRes.body.data.action, 'BLOCK');
    assert.strictEqual(evalRes.body.data.blocklistMatch, true);
  });

  it('DELETE /api/protection/allowlist/:id - reversibly removes entry from allowlist', async () => {
    const policyRes = await request(app)
      .get('/api/protection/policy')
      .set('Authorization', `Bearer ${userAToken}`);

    const entry = policyRes.body.data.allowlist[0];
    assert.ok(entry);

    const delRes = await request(app)
      .delete(`/api/protection/allowlist/${entry._id}`)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(delRes.status, 200);
    assert.strictEqual(delRes.body.success, true);
  });

  it('POST /api/protection/override - logs explicit user override event and persists on policy', async () => {
    const res = await request(app)
      .post('/api/protection/override')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        url: 'http://185.10.20.30/login/verify-account',
        userDecision: 'OVERRIDE',
        reason: 'User bypassed security warning'
      });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.action, 'ALLOW');
    assert.strictEqual(res.body.data.userDecision, 'OVERRIDE');
    assert.ok(Array.isArray(res.body.data.overrides));
    assert.strictEqual(res.body.data.overrides.length, 1);
  });

  it('PERSISTENCE: Fresh evaluation of overridden URL returns action=ALLOW, recommendation=BLOCK, and userDecision=OVERRIDE', async () => {
    const evalRes = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ url: 'http://185.10.20.30/login/verify-account' });

    assert.strictEqual(evalRes.status, 200);
    assert.strictEqual(evalRes.body.success, true);
    assert.strictEqual(evalRes.body.data.riskScore, 78);
    assert.strictEqual(evalRes.body.data.riskLevel, 'HIGH_RISK');
    assert.strictEqual(evalRes.body.data.recommendation, 'BLOCK'); // Base recommendation preserved
    assert.strictEqual(evalRes.body.data.action, 'ALLOW'); // Enforced action is ALLOW due to persisted override
    assert.strictEqual(evalRes.body.data.userDecision, 'OVERRIDE');
    assert.strictEqual(evalRes.body.data.overrideMatch, true);
    assert.ok(evalRes.body.data.reasons.some((r) => r.includes('User override permits access')));
  });

  it('ISOLATION: User B evaluation does NOT inherit User A override', async () => {
    // User B has default ASK_ME mode
    const evalResB = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userBToken}`)
      .send({ url: 'http://185.10.20.30/login/verify-account' });

    assert.strictEqual(evalResB.status, 200);
    assert.strictEqual(evalResB.body.data.riskScore, 78);
    assert.strictEqual(evalResB.body.data.recommendation, 'BLOCK');
    assert.strictEqual(evalResB.body.data.action, 'WARN'); // ASK_ME warns, not overridden
    assert.strictEqual(evalResB.body.data.overrideMatch, false);
  });

  it('PRECEDENCE: Blocklist takes precedence over User A active override', async () => {
    // Add domain to User A blocklist
    await request(app)
      .post('/api/protection/blocklist')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ value: '185.10.20.30', type: 'DOMAIN' });

    const evalRes = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ url: 'http://185.10.20.30/login/verify-account' });

    assert.strictEqual(evalRes.status, 200);
    assert.strictEqual(evalRes.body.data.action, 'BLOCK');
    assert.strictEqual(evalRes.body.data.blocklistMatch, true);

    // Clean up blocklist
    const policyRes = await request(app)
      .get('/api/protection/policy')
      .set('Authorization', `Bearer ${userAToken}`);
    const blockEntry = policyRes.body.data.blocklist.find((b) => b.value === '185.10.20.30');
    if (blockEntry) {
      await request(app)
        .delete(`/api/protection/blocklist/${blockEntry._id}`)
        .set('Authorization', `Bearer ${userAToken}`);
    }
  });

  it('DELETE /api/protection/override - reversibly clears override and falls back to policy', async () => {
    const delRes = await request(app)
      .delete('/api/protection/override')
      .set('Authorization', `Bearer ${userAToken}`)
      .query({ url: 'http://185.10.20.30/login/verify-account' });

    assert.strictEqual(delRes.status, 200);
    assert.strictEqual(delRes.body.success, true);
    assert.strictEqual(delRes.body.data.length, 0);

    // Re-evaluating now falls back to BALANCED policy mode (User A is on BALANCED)
    const evalRes = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ url: 'http://185.10.20.30/login/verify-account' });

    assert.strictEqual(evalRes.status, 200);
    assert.strictEqual(evalRes.body.data.action, 'BLOCK'); // BALANCED blocks high-risk threats
    assert.strictEqual(evalRes.body.data.overrideMatch, false);
  });

  it('GET /api/protection/events & /stats - retrieves user events and stats', async () => {
    const eventsRes = await request(app)
      .get('/api/protection/events?page=1&limit=10')
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(eventsRes.status, 200);
    assert.ok(Array.isArray(eventsRes.body.data));
    assert.ok(eventsRes.body.data.length >= 2);

    const statsRes = await request(app)
      .get('/api/protection/events/stats')
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(statsRes.status, 200);
    assert.ok(statsRes.body.data.totalAnalyzed >= 2);
    assert.ok(typeof statsRes.body.data.currentMode === 'string');
  });

  it('SECURITY: User B cannot access or modify User A policy or events', async () => {
    // User B events should be isolated
    const resB = await request(app)
      .get('/api/protection/events')
      .set('Authorization', `Bearer ${userBToken}`);

    assert.strictEqual(resB.status, 200);
    assert.ok(Array.isArray(resB.body.data));

    // User B policy has independent allowlist
    const policyB = await request(app)
      .get('/api/protection/policy')
      .set('Authorization', `Bearer ${userBToken}`);

    assert.strictEqual(policyB.status, 200);
    assert.strictEqual(policyB.body.data.blocklist.length, 0);
  });
});
