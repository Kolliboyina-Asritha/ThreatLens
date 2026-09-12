process.env.NODE_ENV = 'test';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import mongoose from 'mongoose';
import { ProtectionPolicy } from '../src/models/ProtectionPolicy.js';
import { User } from '../src/models/User.js';
import { env } from '../src/config/env.js';

describe('Phase 3 - ProtectionPolicy Model Unit & Validation Tests', () => {
  let testUser = null;

  before(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(env.MONGODB_URI, { family: 4, serverSelectionTimeoutMS: 5000 });
    }
    await ProtectionPolicy.deleteMany({});
    await User.deleteMany({ email: { $regex: /@policytest\.io$/ } });

    testUser = await User.create({
      name: 'Policy User',
      email: `policy_${Date.now()}@policytest.io`,
      password: 'StrongPassword123!'
    });
  });

  after(async () => {
    await ProtectionPolicy.deleteMany({});
    await User.deleteMany({ email: { $regex: /@policytest\.io$/ } });
    await mongoose.disconnect();
  });

  it('creates a default protection policy with ASK_ME mode and default thresholds', async () => {
    const policy = await ProtectionPolicy.create({
      user: testUser._id
    });

    assert.strictEqual(policy.mode, 'ASK_ME');
    assert.strictEqual(policy.customThresholds.allowMax, 29);
    assert.strictEqual(policy.customThresholds.warnMax, 69);
    assert.strictEqual(Array.isArray(policy.allowlist), true);
    assert.strictEqual(Array.isArray(policy.blocklist), true);
  });

  it('accepts valid custom thresholds when allowMax < warnMax', async () => {
    const policy = await ProtectionPolicy.findOne({ user: testUser._id });
    policy.mode = 'CUSTOM';
    policy.customThresholds = { allowMax: 20, warnMax: 50 };
    await policy.save();

    assert.strictEqual(policy.mode, 'CUSTOM');
    assert.strictEqual(policy.customThresholds.allowMax, 20);
    assert.strictEqual(policy.customThresholds.warnMax, 50);
  });

  it('rejects invalid custom thresholds where allowMax >= warnMax', async () => {
    const policy = await ProtectionPolicy.findOne({ user: testUser._id });
    policy.customThresholds = { allowMax: 70, warnMax: 30 };

    await assert.rejects(async () => {
      await policy.save();
    }, /allowMax must be strictly less than/);
  });

  it('rejects invalid protection mode values', async () => {
    const policy = await ProtectionPolicy.findOne({ user: testUser._id });
    policy.mode = 'INVALID_MODE';

    await assert.rejects(async () => {
      await policy.save();
    });
  });

  it('stores and retrieves persistent user overrides on ProtectionPolicy', async () => {
    const policy = await ProtectionPolicy.findOne({ user: testUser._id });
    policy.mode = 'BALANCED';
    policy.overrides.push({
      url: 'http://185.10.20.30/login/verify-account',
      normalizedUrl: 'http://185.10.20.30/login/verify-account',
      action: 'ALLOW',
      userDecision: 'OVERRIDE',
      reason: 'User accepted risk'
    });
    await policy.save();

    const refreshed = await ProtectionPolicy.findOne({ user: testUser._id });
    assert.strictEqual(refreshed.overrides.length, 1);
    assert.strictEqual(refreshed.overrides[0].normalizedUrl, 'http://185.10.20.30/login/verify-account');
    assert.strictEqual(refreshed.overrides[0].action, 'ALLOW');
    assert.strictEqual(refreshed.overrides[0].userDecision, 'OVERRIDE');
  });
});
