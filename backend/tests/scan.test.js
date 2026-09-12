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

describe('Scan API Endpoints', () => {
  let token = '';
  let userId = '';
  let createdScanId = '';

  before(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(env.MONGODB_URI, { family: 4, serverSelectionTimeoutMS: 5000 });
    }
    await User.deleteMany({ email: { $regex: /@scantest\.io$/ } });
    await Scan.deleteMany({});

    const registerRes = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Scan Tester',
        email: `tester_${Date.now()}@scantest.io`,
        password: 'Password123!'
      });

    token = registerRes.body.data.accessToken;
    userId = registerRes.body.data.user.id;
  });

  after(async () => {
    await User.deleteMany({ email: { $regex: /@scantest\.io$/ } });
    await Scan.deleteMany({});
    await mongoose.disconnect();
  });

  it('POST /api/scan/url - successfully scans a safe HTTPS URL', async () => {
    const res = await request(app)
      .post('/api/scan/url')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'https://www.google.com' });

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.riskLevel, 'SAFE');
    assert.strictEqual(res.body.data.riskScore <= 30, true);
    assert.strictEqual(res.body.data.features.protocol, 'https');
    assert.ok(res.body.data.scanId);
    createdScanId = res.body.data.scanId;
  });

  it('POST /api/scan/url - successfully scans and detects high-risk IP URL with keywords', async () => {
    const res = await request(app)
      .post('/api/scan/url')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'http://185.10.20.30/login/verify-account' });

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.features.isIpAddress, true);
    assert.strictEqual(res.body.data.riskScore > 30, true);
    assert.ok(res.body.data.indicators.length >= 2);
  });

  it('POST /api/scan/url - rejects dangerous scheme javascript:', async () => {
    const res = await request(app)
      .post('/api/scan/url')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'javascript:alert(1)' });

    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.body.success, false);
  });

  it('POST /api/scan/url - rejects file: scheme', async () => {
    const res = await request(app)
      .post('/api/scan/url')
      .set('Authorization', `Bearer ${token}`)
      .send({ url: 'file:///etc/passwd' });

    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.body.success, false);
  });

  it('GET /api/scans - retrieves paginated scan history', async () => {
    const res = await request(app)
      .get('/api/scans?page=1&limit=10')
      .set('Authorization', `Bearer ${token}`);

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(Array.isArray(res.body.data));
    assert.strictEqual(res.body.data.length >= 2, true);
    assert.strictEqual(res.body.meta.page, 1);
    assert.strictEqual(res.body.meta.totalCount >= 2, true);
  });

  it('GET /api/scans/:id - retrieves specific scan details', async () => {
    const res = await request(app)
      .get(`/api/scans/${createdScanId}`)
      .set('Authorization', `Bearer ${token}`);

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.scanId, createdScanId);
    assert.ok(res.body.data.features);
    assert.ok(Array.isArray(res.body.data.indicators));
  });

  it('DELETE /api/scans/:id - deletes scan record', async () => {
    const res = await request(app)
      .delete(`/api/scans/${createdScanId}`)
      .set('Authorization', `Bearer ${token}`);

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);

    // Verify deletion
    const checkRes = await request(app)
      .get(`/api/scans/${createdScanId}`)
      .set('Authorization', `Bearer ${token}`);

    assert.strictEqual(checkRes.status, 404);
  });
});
