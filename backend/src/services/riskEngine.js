import { RISK_LEVELS, RISK_THRESHOLDS } from '../config/constants.js';

/**
 * Calculates a bounded risk score (0-100) and risk level classification from heuristic indicators.
 * 
 * Note: In Phase 1, the scoring is based purely on deterministic heuristic weights.
 * It is not claimed to be statistically calibrated; statistical evaluation and calibration
 * will be integrated in Phase 2 alongside Machine Learning and Threat Intelligence feeds.
 * 
 * @param {Array<{ score: number, severity: string }>} indicators
 * @returns {{ riskScore: number, riskLevel: string, maxPossibleScore: number, indicatorCount: number }}
 */
export const calculateRiskScore = (indicators = []) => {
  if (!Array.isArray(indicators) || indicators.length === 0) {
    return {
      riskScore: 0,
      riskLevel: RISK_LEVELS.SAFE,
      indicatorCount: 0
    };
  }

  // Sum scores from all triggered indicators
  const rawSum = indicators.reduce((acc, curr) => acc + (typeof curr.score === 'number' ? curr.score : 0), 0);

  // Clamp score strictly between 0 and 100
  const riskScore = Math.max(0, Math.min(100, Math.round(rawSum)));

  // Classify level based on defined risk thresholds
  let riskLevel = RISK_LEVELS.SAFE;
  if (riskScore > RISK_THRESHOLDS.SUSPICIOUS_MAX) {
    riskLevel = RISK_LEVELS.HIGH_RISK;
  } else if (riskScore > RISK_THRESHOLDS.SAFE_MAX) {
    riskLevel = RISK_LEVELS.SUSPICIOUS;
  }

  return {
    riskScore,
    riskLevel,
    indicatorCount: indicators.length
  };
};
