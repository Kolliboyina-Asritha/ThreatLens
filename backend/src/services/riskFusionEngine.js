import {
  RISK_LEVELS,
  RISK_THRESHOLDS,
  RISK_FUSION_WEIGHTS
} from '../config/constants.js';

/**
 * Normalizes heuristic indicators into an explicit 0-100 score.
 * @param {Array<{ score: number }>} indicators
 * @returns {number} Score bounded between 0 and 100
 */
export const calculateHeuristicScore = (indicators = []) => {
  if (!Array.isArray(indicators) || indicators.length === 0) return 0;
  const rawSum = indicators.reduce((acc, curr) => acc + (typeof curr.score === 'number' ? curr.score : 0), 0);
  return Math.max(0, Math.min(100, Math.round(rawSum)));
};

/**
 * Combines evidence from Heuristics, Machine Learning, and Threat Intelligence into a unified risk score.
 * 
 * Fusion Formula:
 * Fused Score = sum(w_i' * S_i) where S_i in [0, 100] and sum(w_i') == 1.0.
 * 
 * Dynamic Renormalization:
 * When an engine is unavailable (e.g. ML offline or VT quota reached), active weights
 * are dynamically re-allocated proportionally: w_i' = w_i / sum(w_active).
 * 
 * @param {object} params
 * @param {Array<object>} params.indicators - Heuristic indicators from heuristicEngine
 * @param {object|null} params.ml - Output from mlService
 * @param {object|null} params.threatIntelligence - Output from threatIntelService
 * @returns {object} Unified Risk Evaluation & Component Breakdown
 */
export const fuseRiskEvidence = ({
  indicators = [],
  ml = null,
  threatIntelligence = null
}) => {
  // 1. Compute individual normalized scores (0 to 100)
  const heurScore = calculateHeuristicScore(indicators);

  const isMlAvailable = Boolean(ml && ml.available && typeof ml.probability === 'number');
  const mlScore = isMlAvailable ? Math.max(0, Math.min(100, Math.round(ml.probability * 100))) : null;

  const isTiAvailable = Boolean(threatIntelligence && threatIntelligence.available && typeof threatIntelligence.score === 'number');
  const tiScore = isTiAvailable ? Math.max(0, Math.min(100, Math.round(threatIntelligence.score))) : null;

  // 2. Determine active engines and baseline weights
  const activeEngines = ['heuristics'];
  let weightSum = RISK_FUSION_WEIGHTS.HEURISTICS;

  if (isMlAvailable) {
    activeEngines.push('machineLearning');
    weightSum += RISK_FUSION_WEIGHTS.MACHINE_LEARNING;
  }

  if (isTiAvailable) {
    activeEngines.push('threatIntelligence');
    weightSum += RISK_FUSION_WEIGHTS.THREAT_INTELLIGENCE;
  }

  // 3. Mathematical Dynamic Weight Renormalization
  const normWeightHeur = Number((RISK_FUSION_WEIGHTS.HEURISTICS / weightSum).toFixed(4));
  const normWeightMl = isMlAvailable ? Number((RISK_FUSION_WEIGHTS.MACHINE_LEARNING / weightSum).toFixed(4)) : 0;
  const normWeightTi = isTiAvailable ? Number((RISK_FUSION_WEIGHTS.THREAT_INTELLIGENCE / weightSum).toFixed(4)) : 0;

  // 4. Compute weighted contributions
  const heurContrib = Number((heurScore * normWeightHeur).toFixed(2));
  const mlContrib = isMlAvailable ? Number((mlScore * normWeightMl).toFixed(2)) : 0;
  const tiContrib = isTiAvailable ? Number((tiScore * normWeightTi).toFixed(2)) : 0;

  // 5. Compute fused composite risk score (0 to 100 clamped)
  const rawComposite = heurContrib + mlContrib + tiContrib;
  const riskScore = Math.max(0, Math.min(100, Math.round(rawComposite)));

  // 6. Risk Level Classification
  let riskLevel = RISK_LEVELS.SAFE;
  if (riskScore > RISK_THRESHOLDS.SUSPICIOUS_MAX) {
    riskLevel = RISK_LEVELS.HIGH_RISK;
  } else if (riskScore > RISK_THRESHOLDS.SAFE_MAX) {
    riskLevel = RISK_LEVELS.SUSPICIOUS;
  }

  return {
    riskScore,
    riskLevel,
    riskBreakdown: {
      heuristics: {
        score: heurScore,
        baseWeight: RISK_FUSION_WEIGHTS.HEURISTICS,
        normalizedWeight: normWeightHeur,
        contribution: heurContrib,
        available: true
      },
      machineLearning: {
        score: mlScore,
        probability: isMlAvailable ? ml.probability : null,
        baseWeight: RISK_FUSION_WEIGHTS.MACHINE_LEARNING,
        normalizedWeight: normWeightMl,
        contribution: mlContrib,
        available: isMlAvailable,
        error: ml?.error || null
      },
      threatIntelligence: {
        score: tiScore,
        baseWeight: RISK_FUSION_WEIGHTS.THREAT_INTELLIGENCE,
        normalizedWeight: normWeightTi,
        contribution: tiContrib,
        available: isTiAvailable,
        error: threatIntelligence?.error || null
      },
      activeEngines
    }
  };
};
