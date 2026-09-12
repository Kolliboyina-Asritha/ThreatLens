process.env.NODE_ENV = 'test';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import mongoose from 'mongoose';
import { createApp } from '../src/app.js';
import { User } from '../src/models/User.js';
import { ProtectionPolicy } from '../src/models/ProtectionPolicy.js';
import { SecurityEvent } from '../src/models/SecurityEvent.js';
import { Scan } from '../src/models/Scan.js';
import { env } from '../src/config/env.js';

const app = createApp();

describe('Phase 3 - Security Event Deduplication & Read-Only Evaluation Tests', () => {
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
    await Scan.deleteMany({});
    await User.deleteMany({ email: { $regex: /@dedup-test\.io$/ } });

    // Register User A
    const resA = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Dedup User A',
        email: `dedupa_${Date.now()}@dedup-test.io`,
        password: 'Password123!'
      });
    userAToken = resA.body.data.accessToken;
    userAId = resA.body.data.user.id;

    // Register User B
    const resB = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Dedup User B',
        email: `dedupb_${Date.now()}@dedup-test.io`,
        password: 'Password123!'
      });
    userBToken = resB.body.data.accessToken;
    userBId = resB.body.data.user.id;
  });

  after(async () => {
    await ProtectionPolicy.deleteMany({});
    await SecurityEvent.deleteMany({});
    await Scan.deleteMany({});
    await User.deleteMany({ email: { $regex: /@dedup-test\.io$/ } });
    await mongoose.disconnect();
  });

  it('A. recordAudit:false returns complete evaluation, eventId=null, and creates zero SecurityEvents', async () => {
    const initialEvents = await SecurityEvent.countDocuments({ user: userAId });

    const res = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        url: 'http://192.162.199.186/1.exe',
        recordAudit: false
      });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.eventId, null);
    assert.strictEqual(typeof res.body.data.riskScore, 'number');
    assert.ok(res.body.data.recommendation);
    assert.ok(res.body.data.action);
    assert.ok(res.body.data.riskBreakdown);

    const finalEvents = await SecurityEvent.countDocuments({ user: userAId });
    assert.strictEqual(finalEvents, initialEvents, 'Zero security events must be created when recordAudit: false');
  });

  it('B. Rapid duplicate audited evaluations within 5s create exactly ONE SecurityEvent and reuse eventId', async () => {
    const initialEvents = await SecurityEvent.countDocuments({ user: userAId });

    // Request 1: Audited evaluation
    const res1 = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        url: 'http://192.162.199.186/1.exe',
        recordAudit: true
      });

    assert.strictEqual(res1.status, 200);
    assert.ok(res1.body.data.eventId);
    const eventId1 = res1.body.data.eventId;

    // Request 2: Rapid duplicate evaluation (< 1s later)
    const res2 = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        url: 'http://192.162.199.186/1.exe',
        recordAudit: true
      });

    assert.strictEqual(res2.status, 200);
    assert.strictEqual(res2.body.data.eventId, eventId1, 'Second rapid request must reuse identical eventId');

    const finalEvents = await SecurityEvent.countDocuments({ user: userAId });
    assert.strictEqual(finalEvents, initialEvents + 1, 'Exactly one SecurityEvent must exist for rapid duplicate evaluations');
  });

  it('C. Scan Details: opening or refreshing scan details with recordAudit:false creates zero new SecurityEvents', async () => {
    // 1. Create a Scan
    const scanRes = await request(app)
      .post('/api/scan/url')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ url: 'https://example-forensic-test.com/payload' });

    assert.strictEqual(scanRes.status, 201);
    const scanId = scanRes.body.data.scanId;

    const countBeforeView = await SecurityEvent.countDocuments({ user: userAId });

    // 2. Fetch scan details (simulate viewing ScanDetailsPage)
    const getScanRes = await request(app)
      .get(`/api/scans/${scanId}`)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(getScanRes.status, 200);

    // 3. Simulate frontend read-only evaluateUrl call on mount
    const evalDetailsRes = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        url: getScanRes.body.data.originalUrl,
        recordAudit: false
      });

    assert.strictEqual(evalDetailsRes.status, 200);
    assert.strictEqual(evalDetailsRes.body.data.eventId, null);

    const countAfterView = await SecurityEvent.countDocuments({ user: userAId });
    assert.strictEqual(countAfterView, countBeforeView, 'Viewing or refreshing scan details must not create SecurityEvent');
  });

  it('D. Override: POST override creates exactly ONE event; subsequent recordAudit:false refresh does not create another event', async () => {
    const countBefore = await SecurityEvent.countDocuments({ user: userAId });

    // 1. Record override
    const overrideRes = await request(app)
      .post('/api/protection/override')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        url: 'http://185.10.20.30/login/verify-account',
        userDecision: 'OVERRIDE',
        reason: 'User explicitly confirmed access'
      });

    assert.strictEqual(overrideRes.status, 200);
    assert.ok(overrideRes.body.data.eventId);
    const overrideEventId = overrideRes.body.data.eventId;

    // 2. Refresh evaluation with recordAudit: false (as frontend does)
    const refreshRes = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        url: 'http://185.10.20.30/login/verify-account',
        recordAudit: false
      });

    assert.strictEqual(refreshRes.status, 200);
    assert.strictEqual(refreshRes.body.data.action, 'ALLOW');
    assert.strictEqual(refreshRes.body.data.overrideMatch, true);
    assert.strictEqual(refreshRes.body.data.eventId, null);

    // 3. Verify total new events is exactly 1
    const countAfter = await SecurityEvent.countDocuments({ user: userAId });
    assert.strictEqual(countAfter, countBefore + 1, 'Exactly one event must be logged for override action');

    // 4. Verify rapid duplicate override call also reuses eventId
    const dupOverrideRes = await request(app)
      .post('/api/protection/override')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        url: 'http://185.10.20.30/login/verify-account',
        userDecision: 'OVERRIDE',
        reason: 'User explicitly confirmed access'
      });

    assert.strictEqual(dupOverrideRes.status, 200);
    assert.strictEqual(dupOverrideRes.body.data.eventId, overrideEventId);

    const countAfterDup = await SecurityEvent.countDocuments({ user: userAId });
    assert.strictEqual(countAfterDup, countBefore + 1, 'Duplicate override within 5s must not insert new record');
  });

  it('E. Revert Override: removes override and subsequent read-only evaluation creates zero events', async () => {
    const countBefore = await SecurityEvent.countDocuments({ user: userAId });

    // 1. Remove override
    const delRes = await request(app)
      .delete('/api/protection/override')
      .set('Authorization', `Bearer ${userAToken}`)
      .query({ url: 'http://185.10.20.30/login/verify-account' });

    assert.strictEqual(delRes.status, 200);

    // 2. Read-only refresh
    const refreshRes = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({
        url: 'http://185.10.20.30/login/verify-account',
        recordAudit: false
      });

    assert.strictEqual(refreshRes.status, 200);
    assert.strictEqual(refreshRes.body.data.overrideMatch, false);
    assert.strictEqual(refreshRes.body.data.eventId, null);

    const countAfter = await SecurityEvent.countDocuments({ user: userAId });
    assert.strictEqual(countAfter, countBefore, 'Reverting override and refreshing read-only evaluation creates zero extra events');
  });

  it('F. Different legitimate URLs or actions create distinct SecurityEvents', async () => {
    const countBefore = await SecurityEvent.countDocuments({ user: userAId });

    // Target 1
    const res1 = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ url: 'https://distinct-target-one.org/test1', recordAudit: true });

    // Target 2 (different URL)
    const res2 = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ url: 'https://distinct-target-two.org/test2', recordAudit: true });

    assert.notStrictEqual(res1.body.data.eventId, res2.body.data.eventId, 'Different URLs must have different eventIds');

    const countAfter = await SecurityEvent.countDocuments({ user: userAId });
    assert.strictEqual(countAfter, countBefore + 2, 'Distinct URLs must create distinct SecurityEvent documents');
  });

  it('G. User isolation: User A events are not reused for User B', async () => {
    // User A evaluates a URL
    const resA = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ url: 'https://shared-tested-domain.com/path', recordAudit: true });

    // User B evaluates the EXACT SAME URL at the exact same time
    const resB = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userBToken}`)
      .send({ url: 'https://shared-tested-domain.com/path', recordAudit: true });

    assert.ok(resA.body.data.eventId);
    assert.ok(resB.body.data.eventId);
    assert.notStrictEqual(
      resA.body.data.eventId,
      resB.body.data.eventId,
      'User B must create their own isolated SecurityEvent, never reusing User A event'
    );

    // Verify database document ownership
    const eventA = await SecurityEvent.findById(resA.body.data.eventId);
    const eventB = await SecurityEvent.findById(resB.body.data.eventId);

    assert.strictEqual(eventA.user.toString(), userAId);
    assert.strictEqual(eventB.user.toString(), userBId);
  });
});
