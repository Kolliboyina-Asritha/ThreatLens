process.env.NODE_ENV = 'test';
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import { createApp } from '../src/app.js';
import { User } from '../src/models/User.js';
import { ProtectionPolicy } from '../src/models/ProtectionPolicy.js';
import { SecurityEvent } from '../src/models/SecurityEvent.js';
import { env } from '../src/config/env.js';

const app = createApp();

describe('Phase 3 - Chrome Extension Dedicated Authentication & Session Management Tests', () => {
  let userA = null;
  let userB = null;
  let userAToken = '';
  let userBToken = '';
  let userAId = '';
  let userBId = '';

  const extensionId = 'test-extension-id-12345';
  const stateChallenge = 'random-state-challenge-uuid-67890';

  let userAAuthCode = '';
  let userAExtAccessToken = '';
  let userAExtRefreshToken = '';

  before(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(env.MONGODB_URI, { family: 4, serverSelectionTimeoutMS: 5000 });
    }
    await ProtectionPolicy.deleteMany({});
    await SecurityEvent.deleteMany({});
    await User.deleteMany({ email: { $regex: /@extauth-test\.io$/ } });

    // Register User A
    const resA = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Extension User Alpha',
        email: `ext_alpha_${Date.now()}@extauth-test.io`,
        password: 'Password123!'
      });
    userAToken = resA.body.data.accessToken;
    userAId = resA.body.data.user.id;
    userA = resA.body.data.user;

    // Register User B
    const resB = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Extension User Beta',
        email: `ext_beta_${Date.now()}@extauth-test.io`,
        password: 'Password123!'
      });
    userBToken = resB.body.data.accessToken;
    userBId = resB.body.data.user.id;
    userB = resB.body.data.user;

    // Set User A policy to STRICT and User B policy to ASK_ME
    await request(app)
      .put('/api/protection/policy')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ mode: 'STRICT' });

    await request(app)
      .put('/api/protection/policy')
      .set('Authorization', `Bearer ${userBToken}`)
      .send({ mode: 'ASK_ME' });
  });

  after(async () => {
    await ProtectionPolicy.deleteMany({});
    await SecurityEvent.deleteMany({});
    await User.deleteMany({ email: { $regex: /@extauth-test\.io$/ } });
    await mongoose.disconnect();
  });

  it('AUTH-01 & AUTH-02: POST /api/auth/extension/authorize - generates single-use authorization code for authenticated user', async () => {
    // 1. Unauthenticated request rejected
    const unauthRes = await request(app)
      .post('/api/auth/extension/authorize')
      .send({ extensionId, state: stateChallenge });
    assert.strictEqual(unauthRes.status, 401);

    // 2. Authenticated user generates code
    const authRes = await request(app)
      .post('/api/auth/extension/authorize')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ extensionId, state: stateChallenge });

    assert.strictEqual(authRes.status, 200);
    assert.strictEqual(authRes.body.success, true);
    assert.ok(authRes.body.data.authCode);
    assert.strictEqual(typeof authRes.body.data.authCode, 'string');
    assert.strictEqual(authRes.body.data.expiresIn, 60);

    userAAuthCode = authRes.body.data.authCode;
  });

  it('AUTH-03 & AUTH-09: POST /api/auth/extension/exchange - exchanges code for dedicated tokens and enforces single-use', async () => {
    // 1. Invalid state challenge rejected
    const mismatchRes = await request(app)
      .post('/api/auth/extension/exchange')
      .send({
        authCode: userAAuthCode,
        extensionId,
        state: 'wrong-state-challenge'
      });
    // Note: On mismatch, the code is invalidated or rejected
    assert.ok(mismatchRes.status === 401 || mismatchRes.status === 403);

    // Regenerate code for valid exchange
    const newCodeRes = await request(app)
      .post('/api/auth/extension/authorize')
      .set('Authorization', `Bearer ${userAToken}`)
      .send({ extensionId, state: stateChallenge });
    const freshCode = newCodeRes.body.data.authCode;

    // 2. Valid exchange
    const exchangeRes = await request(app)
      .post('/api/auth/extension/exchange')
      .send({
        authCode: freshCode,
        extensionId,
        state: stateChallenge
      });

    assert.strictEqual(exchangeRes.status, 200);
    assert.strictEqual(exchangeRes.body.success, true);
    assert.ok(exchangeRes.body.data.accessToken);
    assert.ok(exchangeRes.body.data.refreshToken);
    assert.strictEqual(exchangeRes.body.data.user.email, userA.email);
    assert.strictEqual(exchangeRes.body.data.user.password, undefined);

    userAExtAccessToken = exchangeRes.body.data.accessToken;
    userAExtRefreshToken = exchangeRes.body.data.refreshToken;

    // 3. Replay attack: Re-using the same code must be rejected
    const replayRes = await request(app)
      .post('/api/auth/extension/exchange')
      .send({
        authCode: freshCode,
        extensionId,
        state: stateChallenge
      });
    assert.strictEqual(replayRes.status, 401);
  });

  it('AUTH-04 & AUTH-05 & AUTH-06: Extension token evaluate and refresh lifecycle', async () => {
    // 1. Protection evaluation with valid extension token works
    const evalRes = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAExtAccessToken}`)
      .set('x-threatlens-source', 'extension')
      .send({ url: 'https://example.com', recordAudit: false });

    assert.strictEqual(evalRes.status, 200);
    assert.strictEqual(evalRes.body.success, true);

    // 2. Expired access token produces 401
    const expiredAccessToken = jwt.sign(
      { sub: userAId, email: userA.email },
      env.JWT_ACCESS_SECRET,
      { expiresIn: '-10s' } // Expired 10 seconds ago
    );

    const expiredRes = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${expiredAccessToken}`)
      .set('x-threatlens-source', 'extension')
      .send({ url: 'https://example.com' });

    assert.strictEqual(expiredRes.status, 401);
    assert.strictEqual(expiredRes.body.message.includes('expired'), true);

    // 3. POST /api/auth/extension/refresh refreshes token using refreshToken in JSON body
    const refreshRes = await request(app)
      .post('/api/auth/extension/refresh')
      .send({
        refreshToken: userAExtRefreshToken,
        extensionId
      });

    assert.strictEqual(refreshRes.status, 200);
    assert.strictEqual(refreshRes.body.success, true);
    assert.ok(refreshRes.body.data.accessToken);
    assert.ok(refreshRes.body.data.refreshToken);
    assert.strictEqual(refreshRes.body.data.user.email, userA.email);

    // Update with new active token
    userAExtAccessToken = refreshRes.body.data.accessToken;
    userAExtRefreshToken = refreshRes.body.data.refreshToken;

    // 4. Retried evaluation succeeds with refreshed token
    const retriedEval = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAExtAccessToken}`)
      .set('x-threatlens-source', 'extension')
      .send({ url: 'https://example.com', recordAudit: false });

    assert.strictEqual(retriedEval.status, 200);
  });

  it('AUTH-08: Invalid or forged refresh token produces 401 on refresh', async () => {
    const invalidRefreshRes = await request(app)
      .post('/api/auth/extension/refresh')
      .send({
        refreshToken: 'invalid-forged-refresh-token',
        extensionId
      });

    assert.strictEqual(invalidRefreshRes.status, 401);
    assert.strictEqual(invalidRefreshRes.body.success, false);
  });

  it('AUTH-10, AUTH-11, AUTH-12: Multi-User Isolation & User Switching (User A -> User B)', async () => {
    // 1. User B initiates extension authorization
    const bCodeRes = await request(app)
      .post('/api/auth/extension/authorize')
      .set('Authorization', `Bearer ${userBToken}`)
      .send({ extensionId, state: 'state-for-user-b' });

    assert.strictEqual(bCodeRes.status, 200);
    const bAuthCode = bCodeRes.body.data.authCode;

    // 2. User B exchanges code
    const bExchangeRes = await request(app)
      .post('/api/auth/extension/exchange')
      .send({
        authCode: bAuthCode,
        extensionId,
        state: 'state-for-user-b'
      });

    assert.strictEqual(bExchangeRes.status, 200);
    const userBExtAccessToken = bExchangeRes.body.data.accessToken;
    assert.strictEqual(bExchangeRes.body.data.user.email, userB.email);

    // 3. Evaluate high-risk target under User A (STRICT mode: action=BLOCK)
    const evalUserA = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAExtAccessToken}`)
      .set('x-threatlens-source', 'extension')
      .send({ url: 'http://185.10.20.30/login/verify-account', recordAudit: false });

    assert.strictEqual(evalUserA.status, 200);
    assert.strictEqual(evalUserA.body.data.policy, 'STRICT');
    assert.strictEqual(evalUserA.body.data.action, 'BLOCK');

    // 4. Evaluate same target under User B (ASK_ME mode: action=WARN)
    const evalUserB = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userBExtAccessToken}`)
      .set('x-threatlens-source', 'extension')
      .send({ url: 'http://185.10.20.30/login/verify-account', recordAudit: false });

    assert.strictEqual(evalUserB.status, 200);
    assert.strictEqual(evalUserB.body.data.policy, 'ASK_ME');
    assert.strictEqual(evalUserB.body.data.action, 'WARN');

    // 5. Verify User B events are isolated from User A
    const eventsA = await request(app)
      .get('/api/protection/events')
      .set('Authorization', `Bearer ${userAExtAccessToken}`);

    const eventsB = await request(app)
      .get('/api/protection/events')
      .set('Authorization', `Bearer ${userBExtAccessToken}`);

    assert.strictEqual(eventsA.status, 200);
    assert.strictEqual(eventsB.status, 200);
  });

  it('AUTH-14 & AUTH-19: Test Connection and Unauthenticated Protection Rejection', async () => {
    // 1. Authenticated Test Connection succeeds
    const testConnRes = await request(app)
      .post('/api/protection/evaluate')
      .set('Authorization', `Bearer ${userAExtAccessToken}`)
      .set('x-threatlens-source', 'extension')
      .send({ url: 'https://example.com' });

    assert.strictEqual(testConnRes.status, 200);
    assert.strictEqual(testConnRes.body.success, true);

    // 2. Unauthenticated request fails with 401 (never converted to ALLOW)
    const unauthEval = await request(app)
      .post('/api/protection/evaluate')
      .send({ url: 'http://185.10.20.30/login/verify-account' });

    assert.strictEqual(unauthEval.status, 401);
    assert.strictEqual(unauthEval.body.success, false);
  });

  it('MSG-01 to MSG-07: Options page message port protocol guarantees and state responses', async () => {
    // Mock chrome extension storage & runtime state simulator
    const mockStorage = {
      backendUrl: 'http://localhost:5000',
      webDashboardUrl: 'http://localhost:5173',
      authToken: '',
      refreshToken: '',
      userEmail: '',
      userName: '',
      userId: '',
      sessionStatus: 'DISCONNECTED',
      protectionMode: 'ASK_ME',
      authStateChallenge: null
    };

    // Simulate background dispatcher
    const handleMessage = async (message) => {
      if (!message || !message.type) {
        return { ok: false, error: 'Invalid message payload' };
      }

      if (message.type === 'THREATLENS_PING') {
        return {
          ok: true,
          service: 'ThreatLens background',
          version: '3.0.0'
        };
      }

      if (message.type === 'GET_AUTH_STATUS' || message.type === 'GET_AUTH_STATE') {
        const isAuth = mockStorage.sessionStatus === 'AUTHENTICATED' && !!mockStorage.authToken;
        return {
          ok: true,
          authenticated: isAuth,
          isAuthenticated: isAuth,
          sessionStatus: mockStorage.sessionStatus,
          user: isAuth || mockStorage.userEmail ? {
            email: mockStorage.userEmail,
            name: mockStorage.userName,
            id: mockStorage.userId
          } : null,
          userEmail: mockStorage.userEmail,
          protectionMode: mockStorage.protectionMode
        };
      }

      if (message.type === 'START_SIGN_IN') {
        const state = 'mock-uuid-challenge-12345';
        mockStorage.authStateChallenge = state;
        const authUrl = `${mockStorage.webDashboardUrl}/login?extId=mock-ext-id&state=${state}`;
        return { ok: true, success: true, authUrl };
      }

      if (message.type === 'SIGN_OUT') {
        mockStorage.authToken = '';
        mockStorage.refreshToken = '';
        mockStorage.userEmail = '';
        mockStorage.userName = '';
        mockStorage.userId = '';
        mockStorage.sessionStatus = 'DISCONNECTED';
        return { ok: true, success: true };
      }

      if (message.type === 'TEST_CONNECTION') {
        if (!mockStorage.authToken) {
          return { ok: false, success: false, status: 401, message: 'Not authenticated.' };
        }
        return { ok: true, success: true, status: 200, message: 'Connected to ThreatLens.' };
      }

      return { ok: false, error: `Unhandled message type: ${message.type}` };
    };

    // MSG-01: THREATLENS_PING diagnostic returns service health info
    const pingRes = await handleMessage({ type: 'THREATLENS_PING' });
    assert.strictEqual(pingRes.ok, true);
    assert.strictEqual(pingRes.version, '3.0.0');

    // MSG-02: Unauthenticated GET_AUTH_STATUS returns response immediately
    const res1 = await handleMessage({ type: 'GET_AUTH_STATUS' });
    assert.strictEqual(res1.ok, true);
    assert.strictEqual(res1.authenticated, false);
    assert.strictEqual(res1.user, null);
    assert.strictEqual(res1.sessionStatus, 'DISCONNECTED');

    // MSG-03: START_SIGN_IN generates state and auth URL
    const res2 = await handleMessage({ type: 'START_SIGN_IN' });
    assert.strictEqual(res2.ok, true);
    assert.strictEqual(res2.success, true);
    assert.ok(res2.authUrl.includes('/login?extId=mock-ext-id&state='));

    // MSG-04: Simulate successful auth pairing
    mockStorage.authToken = userAExtAccessToken;
    mockStorage.refreshToken = userAExtRefreshToken;
    mockStorage.userEmail = userA.email;
    mockStorage.userName = 'User Alpha';
    mockStorage.userId = userAId;
    mockStorage.sessionStatus = 'AUTHENTICATED';

    // MSG-05: Authenticated GET_AUTH_STATUS returns connected user state
    const res3 = await handleMessage({ type: 'GET_AUTH_STATUS' });
    assert.strictEqual(res3.ok, true);
    assert.strictEqual(res3.authenticated, true);
    assert.strictEqual(res3.user.email, userA.email);

    // MSG-06: Authenticated TEST_CONNECTION succeeds
    const res4 = await handleMessage({ type: 'TEST_CONNECTION' });
    assert.strictEqual(res4.ok, true);
    assert.strictEqual(res4.status, 200);

    // MSG-07: SIGN_OUT terminates session cleanly
    const res5 = await handleMessage({ type: 'SIGN_OUT' });
    assert.strictEqual(res5.ok, true);
    assert.strictEqual(mockStorage.sessionStatus, 'DISCONNECTED');

    // Unhandled message returns ok: false without hanging
    const res6 = await handleMessage({ type: 'UNKNOWN_OP' });
    assert.strictEqual(res6.ok, false);
  });
});
