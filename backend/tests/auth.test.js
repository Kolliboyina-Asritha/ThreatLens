process.env.NODE_ENV = 'test';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import mongoose from 'mongoose';
import { createApp } from '../src/app.js';
import { User } from '../src/models/User.js';
import { env } from '../src/config/env.js';

const app = createApp();

describe('Authentication API Endpoints', () => {
  const testUser = {
    name: 'Alice Security',
    email: `alice_${Date.now()}@threatlens.io`,
    password: 'SuperSecret123!'
  };

  let registeredAccessToken = '';
  let refreshCookie = '';

  before(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(env.MONGODB_URI, { family: 4, serverSelectionTimeoutMS: 5000 });
    }
    await User.deleteMany({ email: { $regex: /@threatlens\.io$/ } });
  });

  after(async () => {
    await User.deleteMany({ email: { $regex: /@threatlens\.io$/ } });
    await mongoose.disconnect();
  });

  it('POST /api/auth/register - successfully registers a new user', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send(testUser);

    assert.strictEqual(res.status, 201);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.user.email, testUser.email.toLowerCase());
    assert.strictEqual(typeof res.body.data.accessToken, 'string');
    assert.strictEqual(res.body.data.user.password, undefined); // Password must not be returned

    registeredAccessToken = res.body.data.accessToken;

    // Check refresh cookie
    const cookies = res.headers['set-cookie'];
    assert.ok(cookies && cookies.length > 0, 'Set-Cookie header should be present');
    refreshCookie = cookies[0];
  });

  it('POST /api/auth/register - rejects duplicate email registration', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send(testUser);

    assert.strictEqual(res.status, 409);
    assert.strictEqual(res.body.success, false);
  });

  it('POST /api/auth/register - rejects weak password (less than 8 chars or no numbers)', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Weak Pass',
        email: 'weak@threatlens.io',
        password: 'short'
      });

    assert.strictEqual(res.status, 400);
    assert.strictEqual(res.body.success, false);
  });

  it('POST /api/auth/login - logs in successfully with valid credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: testUser.email,
        password: testUser.password
      });

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(typeof res.body.data.accessToken, 'string');
    registeredAccessToken = res.body.data.accessToken;
  });

  it('POST /api/auth/login - rejects invalid credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: testUser.email,
        password: 'WrongPassword999!'
      });

    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.body.success, false);
  });

  it('GET /api/auth/me - returns user profile with valid bearer token', async () => {
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${registeredAccessToken}`);

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.user.email, testUser.email.toLowerCase());
  });

  it('GET /api/auth/me - rejects request without token', async () => {
    const res = await request(app).get('/api/auth/me');
    assert.strictEqual(res.status, 401);
  });

  it('POST /api/auth/refresh - generates new access token with valid refresh cookie', async () => {
    const res = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', refreshCookie);

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(typeof res.body.data.accessToken, 'string');
  });

  it('POST /api/auth/logout - clears cookie and returns 200', async () => {
    const res = await request(app).post('/api/auth/logout');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
  });
});
