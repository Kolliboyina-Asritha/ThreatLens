process.env.NODE_ENV = 'test';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateProtectionDecision,
  computeBaseRecommendation,
  checkListMatch
} from '../src/services/protectionDecisionEngine.js';

describe('Phase 3 - Protection Decision Engine Unit Tests', () => {
  it('computes correct base recommendation from risk score', () => {
    assert.strictEqual(computeBaseRecommendation(0), 'ALLOW');
    assert.strictEqual(computeBaseRecommendation(25), 'ALLOW');
    assert.strictEqual(computeBaseRecommendation(30), 'WARN');
    assert.strictEqual(computeBaseRecommendation(69), 'WARN');
    assert.strictEqual(computeBaseRecommendation(70), 'BLOCK');
    assert.strictEqual(computeBaseRecommendation(100), 'BLOCK');
  });

  it('matches domain and URL list items accurately', () => {
    const list = [
      { value: 'malicious-domain.com', type: 'DOMAIN' },
      { value: 'https://evil.com/phish', type: 'URL' }
    ];

    assert.ok(checkListMatch(list, 'http://sub.malicious-domain.com/path', 'sub.malicious-domain.com'));
    assert.ok(checkListMatch(list, 'https://evil.com/phish?id=123', 'evil.com'));
    assert.strictEqual(checkListMatch(list, 'https://benign.com', 'benign.com'), null);
  });

  it('enforces highest precedence for explicit user blocklist match', () => {
    const policy = {
      mode: 'ASK_ME',
      blocklist: [{ value: 'blocked-site.com', type: 'DOMAIN' }]
    };

    const decision = evaluateProtectionDecision({
      riskScore: 10, // Safe score, but blocklisted
      riskLevel: 'SAFE',
      url: 'https://blocked-site.com/home',
      normalizedUrl: 'https://blocked-site.com/home',
      domain: 'blocked-site.com',
      policy
    });

    assert.strictEqual(decision.recommendation, 'BLOCK');
    assert.strictEqual(decision.action, 'BLOCK');
    assert.strictEqual(decision.blocklistMatch, true);
    assert.strictEqual(decision.enforceable, true);
  });

  it('permits user allowlist override for suspicious or risky URLs', () => {
    const policy = {
      mode: 'STRICT',
      allowlist: [{ value: 'trusted-portal.com', type: 'DOMAIN' }]
    };

    const decision = evaluateProtectionDecision({
      riskScore: 78, // High risk, but allowlisted
      riskLevel: 'HIGH_RISK',
      url: 'http://trusted-portal.com/login',
      normalizedUrl: 'http://trusted-portal.com/login',
      domain: 'trusted-portal.com',
      policy
    });

    assert.strictEqual(decision.recommendation, 'BLOCK'); // Base recommendation remains BLOCK
    assert.strictEqual(decision.action, 'ALLOW'); // Action is ALLOW due to allowlist
    assert.strictEqual(decision.allowlistMatch, true);
  });

  it('ASK_ME mode: produces recommendation=BLOCK, action=WARN for high-risk URLs', () => {
    const policy = { mode: 'ASK_ME' };

    const decision = evaluateProtectionDecision({
      riskScore: 78,
      riskLevel: 'HIGH_RISK',
      url: 'http://185.10.20.30/login/verify-account',
      normalizedUrl: 'http://185.10.20.30/login/verify-account',
      domain: '185.10.20.30',
      policy
    });

    assert.strictEqual(decision.recommendation, 'BLOCK');
    assert.strictEqual(decision.action, 'WARN'); // Ask Me mode warns and asks user
    assert.strictEqual(decision.requiresUserConfirmation, true);
  });

  it('BALANCED mode: allows safe, warns suspicious, blocks high risk', () => {
    const policy = { mode: 'BALANCED' };

    const safeDec = evaluateProtectionDecision({
      riskScore: 10,
      riskLevel: 'SAFE',
      domain: 'google.com',
      policy
    });
    assert.strictEqual(safeDec.action, 'ALLOW');

    const warnDec = evaluateProtectionDecision({
      riskScore: 50,
      riskLevel: 'SUSPICIOUS',
      domain: 'suspicious-link.net',
      policy
    });
    assert.strictEqual(warnDec.action, 'WARN');

    const blockDec = evaluateProtectionDecision({
      riskScore: 85,
      riskLevel: 'HIGH_RISK',
      domain: 'malware-host.xyz',
      policy
    });
    assert.strictEqual(blockDec.action, 'BLOCK');
  });

  it('STRICT mode: strictly blocks high-risk threats automatically', () => {
    const policy = { mode: 'STRICT' };

    const decision = evaluateProtectionDecision({
      riskScore: 78,
      riskLevel: 'HIGH_RISK',
      domain: '185.10.20.30',
      policy
    });

    assert.strictEqual(decision.recommendation, 'BLOCK');
    assert.strictEqual(decision.action, 'BLOCK');
    assert.strictEqual(decision.enforceable, true);
  });

  it('CUSTOM mode: enforces custom threshold bounds', () => {
    const policy = {
      mode: 'CUSTOM',
      customThresholds: { allowMax: 15, warnMax: 45 }
    };

    const dec1 = evaluateProtectionDecision({ riskScore: 10, policy });
    assert.strictEqual(dec1.action, 'ALLOW');

    const dec2 = evaluateProtectionDecision({ riskScore: 30, policy });
    assert.strictEqual(dec2.action, 'WARN');

    const dec3 = evaluateProtectionDecision({ riskScore: 50, policy });
    assert.strictEqual(dec3.action, 'BLOCK');
  });

  it('honors explicit user OVERRIDE action', () => {
    const policy = { mode: 'BALANCED' };

    const decision = evaluateProtectionDecision({
      riskScore: 85,
      riskLevel: 'HIGH_RISK',
      domain: 'phish.com',
      policy,
      userDecision: 'OVERRIDE'
    });

    assert.strictEqual(decision.recommendation, 'BLOCK');
    assert.strictEqual(decision.action, 'ALLOW');
    assert.strictEqual(decision.userDecision, 'OVERRIDE');
  });

  it('honors persistent overrides stored in policy.overrides without modifying riskScore or recommendation', () => {
    const policy = {
      mode: 'BALANCED',
      overrides: [
        {
          url: 'http://185.10.20.30/login/verify-account',
          normalizedUrl: 'http://185.10.20.30/login/verify-account',
          action: 'ALLOW',
          userDecision: 'OVERRIDE'
        }
      ]
    };

    const decision = evaluateProtectionDecision({
      riskScore: 78,
      riskLevel: 'HIGH_RISK',
      url: 'http://185.10.20.30/login/verify-account',
      normalizedUrl: 'http://185.10.20.30/login/verify-account',
      domain: '185.10.20.30',
      policy
    });

    assert.strictEqual(decision.recommendation, 'BLOCK');
    assert.strictEqual(decision.action, 'ALLOW');
    assert.strictEqual(decision.userDecision, 'OVERRIDE');
    assert.strictEqual(decision.overrideMatch, true);
    assert.ok(decision.reasons.some((r) => r.includes('User override permits access')));
  });

  it('enforces blocklist precedence over an active user override', () => {
    const policy = {
      mode: 'BALANCED',
      blocklist: [{ value: '185.10.20.30', type: 'DOMAIN' }],
      overrides: [
        {
          url: 'http://185.10.20.30/login/verify-account',
          normalizedUrl: 'http://185.10.20.30/login/verify-account',
          action: 'ALLOW',
          userDecision: 'OVERRIDE'
        }
      ]
    };

    const decision = evaluateProtectionDecision({
      riskScore: 78,
      riskLevel: 'HIGH_RISK',
      url: 'http://185.10.20.30/login/verify-account',
      normalizedUrl: 'http://185.10.20.30/login/verify-account',
      domain: '185.10.20.30',
      policy
    });

    assert.strictEqual(decision.action, 'BLOCK');
    assert.strictEqual(decision.blocklistMatch, true);
  });

  it('enforces allowlist precedence over user override', () => {
    const policy = {
      mode: 'BALANCED',
      allowlist: [{ value: '185.10.20.30', type: 'DOMAIN' }],
      overrides: [
        {
          url: 'http://185.10.20.30/login/verify-account',
          normalizedUrl: 'http://185.10.20.30/login/verify-account',
          action: 'ALLOW',
          userDecision: 'OVERRIDE'
        }
      ]
    };

    const decision = evaluateProtectionDecision({
      riskScore: 78,
      riskLevel: 'HIGH_RISK',
      url: 'http://185.10.20.30/login/verify-account',
      normalizedUrl: 'http://185.10.20.30/login/verify-account',
      domain: '185.10.20.30',
      policy
    });

    assert.strictEqual(decision.action, 'ALLOW');
    assert.strictEqual(decision.allowlistMatch, true);
  });
});
