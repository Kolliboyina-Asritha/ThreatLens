process.env.NODE_ENV = 'test';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { SecurityEvent } from '../src/models/SecurityEvent.js';
import { User } from '../src/models/User.js';
import { env } from '../src/config/env.js';

describe('Phase 3 - SecurityEvent Model Unit & Append-Only Tests', () => {
  let testUser = null;

  before(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(env.MONGODB_URI, { family: 4, serverSelectionTimeoutMS: 5000 });
    }
    await SecurityEvent.deleteMany({});
    await User.deleteMany({ email: { $regex: /@eventtest\.io$/ } });

    testUser = await User.create({
      name: 'Event User',
      email: `event_${Date.now()}@eventtest.io`,
      password: 'StrongPassword123!'
    });
  });

  after(async () => {
    await SecurityEvent.deleteMany({});
    await User.deleteMany({ email: { $regex: /@eventtest\.io$/ } });
    await mongoose.disconnect();
  });

  it('successfully creates an append-only SecurityEvent document', async () => {
    const event = await SecurityEvent.create({
      user: testUser._id,
      url: 'http://185.10.20.30/login',
      normalizedUrl: 'http://185.10.20.30/login',
      domain: '185.10.20.30',
      riskScore: 78,
      riskLevel: 'HIGH_RISK',
      recommendation: 'BLOCK',
      action: 'WARN',
      policyMode: 'ASK_ME',
      userDecision: null,
      source: 'WEB',
      reasonCodes: ['Ask Me mode active: Awaiting user confirmation']
    });

    assert.ok(event._id);
    assert.strictEqual(event.riskScore, 78);
    assert.strictEqual(event.recommendation, 'BLOCK');
    assert.strictEqual(event.action, 'WARN');
    assert.strictEqual(event.policyMode, 'ASK_ME');
  });

  it('rejects invalid action or riskLevel enums', async () => {
    await assert.rejects(async () => {
      await SecurityEvent.create({
        user: testUser._id,
        url: 'https://example.com',
        normalizedUrl: 'https://example.com',
        riskScore: 20,
        riskLevel: 'INVALID_LEVEL',
        recommendation: 'ALLOW',
        action: 'ALLOW',
        policyMode: 'BALANCED'
      });
    });
  });
});
