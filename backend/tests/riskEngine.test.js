import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { calculateRiskScore } from '../src/services/riskEngine.js';
import { RISK_LEVELS } from '../src/config/constants.js';

describe('Risk Engine Scoring & Classification', () => {
  it('returns score 0 and SAFE level for empty indicators', () => {
    const result = calculateRiskScore([]);
    assert.strictEqual(result.riskScore, 0);
    assert.strictEqual(result.riskLevel, RISK_LEVELS.SAFE);
  });

  it('classifies score <= 30 as SAFE', () => {
    const indicators = [{ score: 10, severity: 'LOW' }, { score: 15, severity: 'LOW' }];
    const result = calculateRiskScore(indicators);
    assert.strictEqual(result.riskScore, 25);
    assert.strictEqual(result.riskLevel, RISK_LEVELS.SAFE);
  });

  it('classifies score 31-70 as SUSPICIOUS', () => {
    const indicators = [{ score: 25, severity: 'MEDIUM' }, { score: 25, severity: 'MEDIUM' }];
    const result = calculateRiskScore(indicators);
    assert.strictEqual(result.riskScore, 50);
    assert.strictEqual(result.riskLevel, RISK_LEVELS.SUSPICIOUS);
  });

  it('classifies score 71-100 as HIGH_RISK', () => {
    const indicators = [
      { score: 28, severity: 'HIGH' },
      { score: 20, severity: 'HIGH' },
      { score: 20, severity: 'HIGH' },
      { score: 15, severity: 'MEDIUM' }
    ];
    const result = calculateRiskScore(indicators);
    assert.strictEqual(result.riskScore, 83);
    assert.strictEqual(result.riskLevel, RISK_LEVELS.HIGH_RISK);
  });

  it('clamps maximum score strictly at 100', () => {
    const massiveIndicators = [
      { score: 50, severity: 'CRITICAL' },
      { score: 50, severity: 'CRITICAL' },
      { score: 50, severity: 'CRITICAL' }
    ];
    const result = calculateRiskScore(massiveIndicators);
    assert.strictEqual(result.riskScore, 100);
    assert.strictEqual(result.riskLevel, RISK_LEVELS.HIGH_RISK);
  });

  it('clamps minimum score strictly at 0', () => {
    const negativeIndicators = [{ score: -20, severity: 'LOW' }];
    const result = calculateRiskScore(negativeIndicators);
    assert.strictEqual(result.riskScore, 0);
    assert.strictEqual(result.riskLevel, RISK_LEVELS.SAFE);
  });
});
