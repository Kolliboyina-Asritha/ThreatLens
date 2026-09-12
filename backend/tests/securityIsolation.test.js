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

describe('Security Isolation & Authorization Boundary Tests', () => {
  let userAToken = '';
  let userBToken = '';
  let userAScanId = '';

  before(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(env.MONGODB_URI, { family: 4, serverSelectionTimeoutMS: 5000 });
    }
    await User.deleteMany({ email: { $regex: /@isolation-test\.io$/ } });
    await Scan.deleteMany({});

    // Register User A
    const resA = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'User Alpha',
        email: `alpha_${Date.now()}@isolation-test.io`,
        password: 'Password123!'
      });
    userAToken = resA.body.data.accessToken;

    // Register User B
    const resB = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'User Beta',
        email: `beta_${Date.now()}@isolation-test.io`,
        password: 'Password123!'
      });
    userBToken = resB.body.data.accessToken;

    // User A creates a scan
    const scanRes = await request(app)
      .post('/api/scan/url')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ url: 'https://user-alpha-confidential-target.org' });

    userAScanId = scanRes.body.data.scanId;
  });

  after(async () => {
    await User.deleteMany({ email: { $regex: /@isolation-test\.io$/ } });
    await Scan.deleteMany({});
    await mongoose.disconnect();
  });

  it('SECURITY: User B cannot retrieve User A scan details via GET /api/scans/:id', async () => {
    const res = await request(app)
      .get(`/api/scans/${userAScanId}`)
      .set('Authorization', `Bearer ${userBToken}`);

    // Must return 404 and no data leaked
    assert.strictEqual(res.status, 404);
    assert.strictEqual(res.body.success, false);
    assert.strictEqual(res.body.data, undefined);
  });

  it('SECURITY: User B cannot delete User A scan via DELETE /api/scans/:id', async () => {
    const res = await request(app)
      .delete(`/api/scans/${userAScanId}`)
      .set('Authorization', `Bearer ${userBToken}`);

    assert.strictEqual(res.status, 404);
    assert.strictEqual(res.body.success, false);

    // Verify User A scan is still intact
    const verifyRes = await request(app)
      .get(`/api/scans/${userAScanId}`)
      .set('Authorization', `Bearer ${userAToken}`);

    assert.strictEqual(verifyRes.status, 200);
    assert.strictEqual(verifyRes.body.data.scanId, userAScanId);
  });

  it('SECURITY: User B history does not list User A scans', async () => {
    const res = await request(app)
      .get('/api/scans')
      .set('Authorization', `Bearer ${userBToken}`);

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.data.length, 0);
  });
});
