import {
  PROTECTION_MODES,
  PROTECTION_RECOMMENDATIONS,
  PROTECTION_ACTIONS,
  USER_DECISIONS,
  RISK_LEVELS
} from '../config/constants.js';

/**
 * Checks if a given URL or domain matches any entry in a list (allowlist/blocklist).
 * @param {Array<{ value: string, type: string }>} list
 * @param {string} url
 * @param {string} domain
 * @returns {object|null} Matched entry or null
 */
export const checkListMatch = (list = [], url = '', domain = '') => {
  if (!Array.isArray(list) || list.length === 0) return null;
  const cleanUrl = String(url).toLowerCase().trim();
  const cleanDomain = String(domain).toLowerCase().trim();

  for (const item of list) {
    const itemVal = String(item.value || '').toLowerCase().trim();
    if (!itemVal) continue;

    if (item.type === 'URL') {
      if (cleanUrl === itemVal || cleanUrl.startsWith(itemVal)) {
        return item;
      }
    } else {
      // DOMAIN match: exact domain or subdomain match
      if (cleanDomain === itemVal || cleanDomain.endsWith(`.${itemVal}`)) {
        return item;
      }
    }
  }
  return null;
};

/**
 * Checks if a given URL matches any active user override in the policy.
 * @param {Array<{ normalizedUrl: string, url: string }>} overrides
 * @param {string} normalizedUrl
 * @param {string} url
 * @returns {object|null} Matched override entry or null
 */
export const checkOverrideMatch = (overrides = [], normalizedUrl = '', url = '') => {
  if (!Array.isArray(overrides) || overrides.length === 0) return null;
  const cleanNorm = String(normalizedUrl || '').toLowerCase().trim();
  const cleanUrl = String(url || '').toLowerCase().trim();

  for (const item of overrides) {
    const itemNorm = String(item.normalizedUrl || '').toLowerCase().trim();
    const itemUrl = String(item.url || '').toLowerCase().trim();
    if (itemNorm && (cleanNorm === itemNorm || cleanNorm.startsWith(itemNorm))) {
      return item;
    }
    if (itemUrl && (cleanUrl === itemUrl || cleanUrl.startsWith(itemUrl))) {
      return item;
    }
  }
  return null;
};

/**
 * Computes base ThreatLens security recommendation strictly from risk score.
 * (Separated from user enforcement policy).
 * @param {number} riskScore - 0 to 100
 * @returns {string} 'ALLOW' | 'WARN' | 'BLOCK'
 */
export const computeBaseRecommendation = (riskScore = 0) => {
  if (riskScore >= 70) return PROTECTION_RECOMMENDATIONS.BLOCK;
  if (riskScore >= 30) return PROTECTION_RECOMMENDATIONS.WARN;
  return PROTECTION_RECOMMENDATIONS.ALLOW;
};

/**
 * Pure deterministic protection decision engine.
 * Maps deterministic threat analysis to user-configured protection policy and enforcement action.
 * 
 * Precedence:
 * 1. User Blocklist Match -> BLOCK (enforced)
 * 2. User Allowlist Match -> ALLOW (user-trusted override)
 * 3. User Explicit Override -> ALLOW (recorded as OVERRIDE)
 * 4. User Policy Mode Evaluation (ASK_ME, BALANCED, STRICT, CUSTOM)
 * 
 * @param {object} params
 * @param {number} params.riskScore - 0 to 100
 * @param {string} params.riskLevel - 'SAFE' | 'SUSPICIOUS' | 'HIGH_RISK'
 * @param {string} params.url - Original URL string
 * @param {string} params.normalizedUrl - Normalized URL string
 * @param {string} params.domain - Extracted domain/hostname
 * @param {object} params.policy - ProtectionPolicy document/object
 * @param {string|null} params.userDecision - Explicit user action ('ALLOW', 'WARN', 'BLOCK', 'OVERRIDE')
 * @returns {object} Structured Decision Output
 */
export const evaluateProtectionDecision = ({
  riskScore = 0,
  riskLevel = RISK_LEVELS.SAFE,
  url = '',
  normalizedUrl = '',
  domain = '',
  policy = null,
  userDecision = null
}) => {
  const boundedScore = Math.max(0, Math.min(100, Math.round(riskScore)));
  const baseRecommendation = computeBaseRecommendation(boundedScore);
  const activeMode = policy?.mode || PROTECTION_MODES.ASK_ME;

  const reasons = [];
  let reasonCode = 'POLICY_EVALUATED';
  let matchedRule = null;
  let blocklistMatch = false;
  let allowlistMatch = false;
  let recommendation = baseRecommendation;
  let action = PROTECTION_ACTIONS.ALLOW;
  let requiresUserConfirmation = false;
  let enforceable = false;

  // 1. Check User Blocklist Precedence
  const blockEntry = checkListMatch(policy?.blocklist, normalizedUrl || url, domain);
  if (blockEntry) {
    blocklistMatch = true;
    matchedRule = `Blocklist match: ${blockEntry.value} (${blockEntry.type})`;
    reasonCode = 'MATCHED_BLOCKLIST';
    recommendation = PROTECTION_RECOMMENDATIONS.BLOCK;
    action = PROTECTION_ACTIONS.BLOCK;
    enforceable = true;
    requiresUserConfirmation = false;
    reasons.push(`This destination was explicitly placed on your personal blocklist (${blockEntry.value}).`);
    return {
      recommendation,
      action,
      policyMode: activeMode,
      reasonCode,
      matchedRule,
      requiresUserConfirmation,
      enforceable,
      blocklistMatch,
      allowlistMatch,
      reasons,
      userDecision: userDecision || USER_DECISIONS.BLOCK
    };
  }

  // 2. Check User Allowlist Precedence
  const allowEntry = checkListMatch(policy?.allowlist, normalizedUrl || url, domain);
  if (allowEntry) {
    allowlistMatch = true;
    matchedRule = `Allowlist match: ${allowEntry.value} (${allowEntry.type})`;
    reasonCode = 'MATCHED_ALLOWLIST';
    recommendation = baseRecommendation;
    action = PROTECTION_ACTIONS.ALLOW;
    enforceable = false;
    requiresUserConfirmation = false;
    reasons.push(`This destination matches your personal trusted allowlist (${allowEntry.value}).`);
    if (baseRecommendation !== PROTECTION_RECOMMENDATIONS.ALLOW) {
      reasons.push(`Note: Automated security analysis scored this URL at ${boundedScore}/100 (${riskLevel}), but your personal allowlist permits access.`);
    }
    return {
      recommendation,
      action,
      policyMode: activeMode,
      reasonCode,
      matchedRule,
      requiresUserConfirmation,
      enforceable,
      blocklistMatch,
      allowlistMatch,
      reasons,
      userDecision: userDecision || USER_DECISIONS.ALLOW
    };
  }

  // 3. Check Active User Override Precedence (Persisted in policy.overrides or passed as userDecision)
  const activeOverride = checkOverrideMatch(policy?.overrides, normalizedUrl || url, url);
  if (activeOverride || userDecision === USER_DECISIONS.OVERRIDE) {
    reasonCode = 'USER_OVERRIDE';
    recommendation = baseRecommendation;
    action = PROTECTION_ACTIONS.ALLOW;
    enforceable = false;
    requiresUserConfirmation = false;
    reasons.push(
      baseRecommendation !== PROTECTION_RECOMMENDATIONS.ALLOW
        ? `User override permits access despite the ${baseRecommendation} recommendation.`
        : 'User override permits access.'
    );
    return {
      recommendation,
      action,
      policyMode: activeMode,
      reasonCode,
      matchedRule: 'User Override Executed',
      requiresUserConfirmation,
      enforceable,
      blocklistMatch,
      allowlistMatch,
      overrideMatch: true,
      reasons,
      userDecision: USER_DECISIONS.OVERRIDE
    };
  }

  // 4. Policy Mode Evaluation
  switch (activeMode) {
    case PROTECTION_MODES.ASK_ME:
      // Ask Me Mode: Never silently or automatically block. Show recommendation and ask user.
      if (baseRecommendation === PROTECTION_RECOMMENDATIONS.ALLOW) {
        action = PROTECTION_ACTIONS.ALLOW;
        requiresUserConfirmation = false;
        reasonCode = 'ASK_ME_SAFE';
        reasons.push('URL evaluated as safe. No threat indicators requiring confirmation.');
      } else {
        action = PROTECTION_ACTIONS.WARN;
        requiresUserConfirmation = true;
        reasonCode = 'ASK_ME_CONFIRMATION_REQUIRED';
        reasons.push(
          `Ask Me mode active: ThreatLens recommendation is ${baseRecommendation} (Score: ${boundedScore}/100), awaiting your decision.`
        );
      }
      break;

    case PROTECTION_MODES.BALANCED:
      // Balanced Mode: 0-29 ALLOW, 30-69 WARN, 70-100 BLOCK with override option
      if (boundedScore < 30) {
        action = PROTECTION_ACTIONS.ALLOW;
        requiresUserConfirmation = false;
        reasonCode = 'BALANCED_ALLOW';
        reasons.push('URL threat score within safe threshold (0–29). Access allowed.');
      } else if (boundedScore < 70) {
        action = PROTECTION_ACTIONS.WARN;
        requiresUserConfirmation = true;
        reasonCode = 'BALANCED_WARN';
        reasons.push('URL threat score indicates suspicious indicators (30–69). Security warning presented.');
      } else {
        action = PROTECTION_ACTIONS.BLOCK;
        requiresUserConfirmation = false;
        enforceable = true;
        reasonCode = 'BALANCED_BLOCK';
        reasons.push('URL threat score indicates high-risk threat (70–100). Connection blocked by Balanced policy.');
      }
      break;

    case PROTECTION_MODES.STRICT:
      // Strict Mode: Automatically enforce blocking on high risk and warning on suspicious
      if (boundedScore < 30) {
        action = PROTECTION_ACTIONS.ALLOW;
        requiresUserConfirmation = false;
        reasonCode = 'STRICT_ALLOW';
        reasons.push('URL threat score verified safe (0–29). Access allowed.');
      } else if (boundedScore < 70) {
        action = PROTECTION_ACTIONS.WARN;
        requiresUserConfirmation = true;
        reasonCode = 'STRICT_WARN';
        reasons.push('Strict policy: Suspicious indicators detected (30–69). User review required.');
      } else {
        action = PROTECTION_ACTIONS.BLOCK;
        requiresUserConfirmation = false;
        enforceable = true;
        reasonCode = 'STRICT_BLOCK_ENFORCED';
        reasons.push('Strict policy: High-risk threat automatically blocked (70–100).');
      }
      break;

    case PROTECTION_MODES.CUSTOM:
      // Custom Mode: Use user-defined thresholds
      const allowMax = typeof policy?.customThresholds?.allowMax === 'number' ? policy.customThresholds.allowMax : 29;
      const warnMax = typeof policy?.customThresholds?.warnMax === 'number' ? policy.customThresholds.warnMax : 69;

      if (boundedScore <= allowMax) {
        action = PROTECTION_ACTIONS.ALLOW;
        requiresUserConfirmation = false;
        reasonCode = 'CUSTOM_ALLOW';
        reasons.push(`Threat score ${boundedScore} is within custom safe threshold (<= ${allowMax}).`);
      } else if (boundedScore <= warnMax) {
        action = PROTECTION_ACTIONS.WARN;
        requiresUserConfirmation = true;
        reasonCode = 'CUSTOM_WARN';
        reasons.push(`Threat score ${boundedScore} is within custom warning threshold (${allowMax + 1}–${warnMax}).`);
      } else {
        action = PROTECTION_ACTIONS.BLOCK;
        requiresUserConfirmation = false;
        enforceable = true;
        reasonCode = 'CUSTOM_BLOCK';
        reasons.push(`Threat score ${boundedScore} exceeds custom warning threshold (> ${warnMax}). Blocked.`);
      }
      break;

    default:
      action = PROTECTION_ACTIONS.ALLOW;
      requiresUserConfirmation = false;
      reasonCode = 'DEFAULT_ALLOW';
      reasons.push('Default protection evaluation applied.');
  }

  return {
    recommendation,
    action,
    policyMode: activeMode,
    reasonCode,
    matchedRule,
    requiresUserConfirmation,
    enforceable,
    blocklistMatch,
    allowlistMatch,
    reasons,
    userDecision: userDecision || null
  };
};
