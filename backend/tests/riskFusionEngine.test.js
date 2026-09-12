process.env.NODE_ENV = 'test';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  calculateHeuristicScore,
  fuseRiskEvidence
} from '../src/services/riskFusionEngine.js';
import { RISK_LEVELS } from '../src/config/constants.js';

describe('Phase 2 - Unified Risk Fusion Engine Unit Tests', () => {
  it('calculates heuristic score bounded [0, 100]', () => {
    assert.strictEqual(calculateHeuristicScore([]), 0);
    assert.strictEqual(calculateHeuristicScore([{ score: 10 }, { score: 15 }]), 25);
    // Clamping at 100
    assert.strictEqual(calculateHeuristicScore([{ score: 60 }, { score: 60 }]), 100);
  });

  it('fuses single engine (Heuristics-only) with dynamic re-weighting to 1.0', () => {
    const indicators = [{ score: 20 }];
    const fused = fuseRiskEvidence({
      indicators,
      ml: { available: false },
      threatIntelligence: { available: false }
    });

    assert.strictEqual(fused.riskScore, 20);
    assert.strictEqual(fused.riskLevel, RISK_LEVELS.SAFE);
    assert.strictEqual(fused.riskBreakdown.heuristics.normalizedWeight, 1.0);
    assert.strictEqual(fused.riskBreakdown.machineLearning.available, false);
    assert.strictEqual(fused.riskBreakdown.threatIntelligence.available, false);
  });

  it('fuses two engines (Heuristics + ML) with proportional weight redistribution', () => {
    const indicators = [{ score: 50 }]; // Heuristics = 50
    const ml = { available: true, probability: 0.80 }; // ML score = 80

    // Base weights: Heur = 0.35, ML = 0.40 (Sum = 0.75)
    // Normalized weights: Heur = 0.35/0.75 = 0.4667, ML = 0.40/0.75 = 0.5333
    // Composite = 50 * 0.4667 + 80 * 0.5333 = 23.335 + 42.664 = 66
    const fused = fuseRiskEvidence({
      indicators,
      ml,
      threatIntelligence: { available: false }
    });

    assert.strictEqual(fused.riskScore, 66);
    assert.strictEqual(fused.riskLevel, RISK_LEVELS.SUSPICIOUS);
    assert.strictEqual(fused.riskBreakdown.heuristics.normalizedWeight, 0.4667);
    assert.strictEqual(fused.riskBreakdown.machineLearning.normalizedWeight, 0.5333);
    assert.deepStrictEqual(fused.riskBreakdown.activeEngines, ['heuristics', 'machineLearning']);
  });

  it('fuses all three engines (Heuristics + ML + Threat Intel)', () => {
    const indicators = [{ score: 70 }]; // Heuristics = 70
    const ml = { available: true, probability: 0.90 }; // ML = 90
    const threatIntelligence = { available: true, score: 100 }; // TI = 100

    // Base weights: Heur = 0.35, ML = 0.40, TI = 0.25 (Sum = 1.0)
    // Composite = 70 * 0.35 + 90 * 0.40 + 100 * 0.25 = 24.5 + 36 + 25 = 85.5 -> 86
    const fused = fuseRiskEvidence({
      indicators,
      ml,
      threatIntelligence
    });

    assert.strictEqual(fused.riskScore, 86);
    assert.strictEqual(fused.riskLevel, RISK_LEVELS.HIGH_RISK);
    assert.strictEqual(fused.riskBreakdown.heuristics.normalizedWeight, 0.35);
    assert.strictEqual(fused.riskBreakdown.machineLearning.normalizedWeight, 0.40);
    assert.strictEqual(fused.riskBreakdown.threatIntelligence.normalizedWeight, 0.25);
    assert.deepStrictEqual(fused.riskBreakdown.activeEngines, ['heuristics', 'machineLearning', 'threatIntelligence']);
  });

  it('strictly clamps fused risk score between 0 and 100', () => {
    const high = fuseRiskEvidence({
      indicators: [{ score: 150 }],
      ml: { available: true, probability: 1.0 },
      threatIntelligence: { available: true, score: 100 }
    });
    assert.strictEqual(high.riskScore, 100);

    const low = fuseRiskEvidence({
      indicators: [],
      ml: { available: true, probability: 0.0 },
      threatIntelligence: { available: true, score: 0 }
    });
    assert.strictEqual(low.riskScore, 0);
  });
});
