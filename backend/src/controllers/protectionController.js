import mongoose from 'mongoose';
import { ProtectionPolicy } from '../models/ProtectionPolicy.js';
import { SecurityEvent } from '../models/SecurityEvent.js';
import {
  evaluateProtectionSchema,
  updatePolicySchema,
  addListEntrySchema,
  recordOverrideSchema
} from '../validators/protectionValidators.js';
import { extractUrlFeatures } from '../services/urlAnalyzer.js';
import { evaluateHeuristics } from '../services/heuristicEngine.js';
import { predictThreatWithML } from '../services/mlService.js';
import { getThreatIntelligence } from '../services/threatIntelService.js';
import { fuseRiskEvidence } from '../services/riskFusionEngine.js';
import { explainThreatEvidence } from '../services/llmService.js';
import { evaluateProtectionDecision } from '../services/protectionDecisionEngine.js';
import { successResponse, errorResponse } from '../utils/apiResponse.js';

/**
 * Helper to ensure a user always has an active ProtectionPolicy document.
 * @param {string|mongoose.Types.ObjectId} userId
 * @returns {Promise<Document>}
 */
const getOrCreateUserPolicy = async (userId) => {
  let policy = await ProtectionPolicy.findOne({ user: userId });
  if (!policy) {
    policy = await ProtectionPolicy.create({
      user: userId,
      mode: 'ASK_ME',
      customThresholds: { allowMax: 29, warnMax: 69 },
      allowlist: [],
      blocklist: []
    });
  }
  return policy;
};

// GET /api/protection/policy
export const getPolicy = async (req, res, next) => {
  try {
    const policy = await getOrCreateUserPolicy(req.user._id);
    return successResponse(res, 200, 'Protection policy retrieved successfully.', policy);
  } catch (error) {
    next(error);
  }
};

// PUT /api/protection/policy
export const updatePolicy = async (req, res, next) => {
  try {
    const validated = updatePolicySchema.parse(req.body);
    const policy = await getOrCreateUserPolicy(req.user._id);

    if (validated.mode) {
      policy.mode = validated.mode;
    }
    if (validated.customThresholds) {
      policy.customThresholds = {
        ...policy.customThresholds,
        ...validated.customThresholds
      };
    }

    await policy.save();
    return successResponse(res, 200, 'Protection policy updated successfully.', policy);
  } catch (error) {
    next(error);
  }
};

// POST /api/protection/evaluate (or check)
export const evaluateUrl = async (req, res, next) => {
  try {
    const validated = evaluateProtectionSchema.parse(req.body);
    const { url } = validated;
    const shouldRecordAudit =
      validated.recordAudit !== false &&
      req.query?.recordAudit !== 'false' &&
      req.headers['x-threatlens-audit'] !== 'false';

    // 1. Get user policy
    const policy = await getOrCreateUserPolicy(req.user._id);

    // 2. SSRF-Safe Feature Extraction
    const features = extractUrlFeatures(url);

    // 3. Heuristic Rules Evaluation
    const indicators = evaluateHeuristics(features);

    // 4. Parallel ML & Threat Intelligence Lookups
    const [mlSettled, tiSettled] = await Promise.allSettled([
      predictThreatWithML(features),
      getThreatIntelligence(features.normalizedUrl)
    ]);

    const mlResult = mlSettled.status === 'fulfilled'
      ? mlSettled.value
      : { available: false, error: mlSettled.reason?.message || 'ML service failure' };

    const tiResult = tiSettled.status === 'fulfilled'
      ? tiSettled.value
      : { available: false, error: tiSettled.reason?.message || 'Threat Intelligence failure' };

    // 5. Multi-Engine Risk Fusion
    const { riskScore, riskLevel, riskBreakdown } = fuseRiskEvidence({
      indicators,
      ml: mlResult,
      threatIntelligence: tiResult
    });

    // 6. AI Explanation Synthesis (Advisory only)
    const aiExplanation = await explainThreatEvidence({
      url: features.originalUrl,
      riskScore,
      riskLevel,
      indicators,
      ml: mlResult,
      threatIntelligence: tiResult,
      features
    });

    // 7. Protection Decision Engine (Separated Policy Enforcement)
    const domain = features.hostname || features.domain || '';
    const decision = evaluateProtectionDecision({
      riskScore,
      riskLevel,
      url: features.originalUrl,
      normalizedUrl: features.normalizedUrl,
      domain,
      policy
    });

    // 8. Log Append-Only Security Event (if audited)
    let eventId = null;
    if (shouldRecordAudit) {
      const sourceHeader = req.headers['x-threatlens-source'];
      const source = sourceHeader === 'extension' ? 'EXTENSION' : 'WEB';

      const fiveSecondsAgo = new Date(Date.now() - 5000);
      const recentEvent = await SecurityEvent.findOne({
        user: req.user._id,
        normalizedUrl: features.normalizedUrl,
        action: decision.action,
        userDecision: decision.userDecision,
        createdAt: { $gte: fiveSecondsAgo }
      }).sort({ createdAt: -1 });

      if (recentEvent) {
        eventId = recentEvent._id;
      } else {
        const event = await SecurityEvent.create({
          user: req.user._id,
          url: features.originalUrl,
          normalizedUrl: features.normalizedUrl,
          domain,
          riskScore,
          riskLevel,
          recommendation: decision.recommendation,
          action: decision.action,
          policyMode: decision.policyMode,
          userDecision: decision.userDecision,
          source,
          reasonCodes: decision.reasons,
          analysisVersion: '3.0.0'
        });
        eventId = event._id;
      }
    }

    return successResponse(res, 200, 'Protection evaluation completed successfully.', {
      eventId,
      url: features.originalUrl,
      normalizedUrl: features.normalizedUrl,
      domain,
      riskScore,
      riskLevel,
      recommendation: decision.recommendation,
      action: decision.action,
      policy: decision.policyMode,
      userDecision: decision.userDecision,
      reasons: decision.reasons,
      matchedRule: decision.matchedRule,
      requiresUserConfirmation: decision.requiresUserConfirmation,
      enforceable: decision.enforceable,
      allowlistMatch: decision.allowlistMatch,
      blocklistMatch: decision.blocklistMatch,
      overrideMatch: decision.overrideMatch || false,
      riskBreakdown,
      aiExplanation,
      indicators,
      features,
      analysisVersion: '3.0.0'
    });
  } catch (error) {
    next(error);
  }
};

// GET /api/protection/events
export const getEvents = async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 10));
    const skip = (page - 1) * limit;

    const filter = { user: req.user._id };
    if (req.query.action) {
      filter.action = req.query.action.toUpperCase();
    }
    if (req.query.riskLevel) {
      filter.riskLevel = req.query.riskLevel.toUpperCase();
    }

    const [events, totalCount] = await Promise.all([
      SecurityEvent.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      SecurityEvent.countDocuments(filter)
    ]);

    const totalPages = Math.ceil(totalCount / limit);

    return successResponse(res, 200, 'Security events retrieved successfully.', events, {
      page,
      limit,
      totalCount,
      totalPages,
      hasNextPage: page < totalPages,
      hasPrevPage: page > 1
    });
  } catch (error) {
    next(error);
  }
};

// GET /api/protection/events/stats
export const getEventStats = async (req, res, next) => {
  try {
    const userId = req.user._id;

    const [events, policy] = await Promise.all([
      SecurityEvent.find({ user: userId }).lean(),
      getOrCreateUserPolicy(userId)
    ]);

    const totalAnalyzed = events.length;
    const allowed = events.filter((e) => e.action === 'ALLOW').length;
    const warned = events.filter((e) => e.action === 'WARN').length;
    const blocked = events.filter((e) => e.action === 'BLOCK').length;
    const overrides = events.filter((e) => e.userDecision === 'OVERRIDE').length;

    const safeCount = events.filter((e) => e.riskLevel === 'SAFE').length;
    const suspiciousCount = events.filter((e) => e.riskLevel === 'SUSPICIOUS').length;
    const highRiskCount = events.filter((e) => e.riskLevel === 'HIGH_RISK').length;

    return successResponse(res, 200, 'Protection statistics retrieved successfully.', {
      totalAnalyzed,
      allowed,
      warned,
      blocked,
      overrides,
      allowlistCount: policy.allowlist?.length || 0,
      blocklistCount: policy.blocklist?.length || 0,
      currentMode: policy.mode,
      riskDistribution: {
        safe: safeCount,
        suspicious: suspiciousCount,
        highRisk: highRiskCount
      }
    });
  } catch (error) {
    next(error);
  }
};

// POST /api/protection/allowlist
export const addAllowlistEntry = async (req, res, next) => {
  try {
    const { value, type } = addListEntrySchema.parse(req.body);
    const policy = await getOrCreateUserPolicy(req.user._id);

    const cleanValue = value.toLowerCase().trim();

    // Prevent duplicate entries
    const exists = policy.allowlist.some(
      (item) => item.value === cleanValue && item.type === type
    );
    if (exists) {
      return errorResponse(res, 409, 'Entry already exists in your allowlist.');
    }

    // Also remove from blocklist if previously blocklisted
    policy.blocklist = policy.blocklist.filter((item) => item.value !== cleanValue);

    policy.allowlist.push({
      value: cleanValue,
      type,
      addedAt: new Date()
    });

    await policy.save();
    return successResponse(res, 201, 'Domain/URL added to allowlist successfully.', policy.allowlist);
  } catch (error) {
    next(error);
  }
};

// DELETE /api/protection/allowlist/:id
export const removeAllowlistEntry = async (req, res, next) => {
  try {
    const { id } = req.params;
    const policy = await getOrCreateUserPolicy(req.user._id);

    const initialLen = policy.allowlist.length;
    policy.allowlist = policy.allowlist.filter(
      (item) => item._id.toString() !== id && item.value !== id.toLowerCase().trim()
    );

    if (policy.allowlist.length === initialLen) {
      return errorResponse(res, 404, 'Allowlist entry not found.');
    }

    await policy.save();
    return successResponse(res, 200, 'Entry removed from allowlist successfully.', policy.allowlist);
  } catch (error) {
    next(error);
  }
};

// POST /api/protection/blocklist
export const addBlocklistEntry = async (req, res, next) => {
  try {
    const { value, type } = addListEntrySchema.parse(req.body);
    const policy = await getOrCreateUserPolicy(req.user._id);

    const cleanValue = value.toLowerCase().trim();

    // Prevent duplicate entries
    const exists = policy.blocklist.some(
      (item) => item.value === cleanValue && item.type === type
    );
    if (exists) {
      return errorResponse(res, 409, 'Entry already exists in your blocklist.');
    }

    // Also remove from allowlist if previously allowlisted
    policy.allowlist = policy.allowlist.filter((item) => item.value !== cleanValue);

    policy.blocklist.push({
      value: cleanValue,
      type,
      addedAt: new Date()
    });

    await policy.save();
    return successResponse(res, 201, 'Domain/URL added to blocklist successfully.', policy.blocklist);
  } catch (error) {
    next(error);
  }
};

// DELETE /api/protection/blocklist/:id
export const removeBlocklistEntry = async (req, res, next) => {
  try {
    const { id } = req.params;
    const policy = await getOrCreateUserPolicy(req.user._id);

    const initialLen = policy.blocklist.length;
    policy.blocklist = policy.blocklist.filter(
      (item) => item._id.toString() !== id && item.value !== id.toLowerCase().trim()
    );

    if (policy.blocklist.length === initialLen) {
      return errorResponse(res, 404, 'Blocklist entry not found.');
    }

    await policy.save();
    return successResponse(res, 200, 'Entry removed from blocklist successfully.', policy.blocklist);
  } catch (error) {
    next(error);
  }
};

// POST /api/protection/override
export const recordOverride = async (req, res, next) => {
  try {
    const { url, userDecision, reason } = recordOverrideSchema.parse(req.body);

    const features = extractUrlFeatures(url);
    const policy = await getOrCreateUserPolicy(req.user._id);
    const domain = features.hostname || features.domain || '';
    const normUrl = (features.normalizedUrl || url).toLowerCase().trim();

    // 1. Persist override in user's ProtectionPolicy (replacing existing for the same normalized URL)
    policy.overrides = (policy.overrides || []).filter(
      (item) => item.normalizedUrl !== normUrl && item.url.toLowerCase().trim() !== url.toLowerCase().trim()
    );
    policy.overrides.push({
      url: features.originalUrl,
      normalizedUrl: normUrl,
      action: 'ALLOW',
      userDecision: userDecision || 'OVERRIDE',
      reason: reason || 'User explicitly chose to bypass security warning and proceed.',
      createdAt: new Date()
    });
    await policy.save();

    // 2. Record override security event with 5-second idempotency check
    const fiveSecondsAgo = new Date(Date.now() - 5000);
    const recentEvent = await SecurityEvent.findOne({
      user: req.user._id,
      normalizedUrl: features.normalizedUrl,
      action: 'ALLOW',
      userDecision: userDecision || 'OVERRIDE',
      createdAt: { $gte: fiveSecondsAgo }
    }).sort({ createdAt: -1 });

    let eventId = null;
    if (recentEvent) {
      eventId = recentEvent._id;
    } else {
      const event = await SecurityEvent.create({
        user: req.user._id,
        url: features.originalUrl,
        normalizedUrl: features.normalizedUrl,
        domain,
        riskScore: 70, // Overridden event
        riskLevel: 'HIGH_RISK',
        recommendation: 'BLOCK',
        action: 'ALLOW',
        policyMode: policy.mode,
        userDecision: userDecision || 'OVERRIDE',
        source: req.headers['x-threatlens-source'] === 'extension' ? 'EXTENSION' : 'WEB',
        reasonCodes: [reason || 'User explicitly chose to bypass security warning and proceed.'],
        analysisVersion: '3.0.0'
      });
      eventId = event._id;
    }

    return successResponse(res, 200, 'User override recorded successfully.', {
      eventId,
      url: features.originalUrl,
      normalizedUrl: features.normalizedUrl,
      action: 'ALLOW',
      userDecision: 'OVERRIDE',
      overrides: policy.overrides
    });
  } catch (error) {
    next(error);
  }
};

// DELETE /api/protection/override/:id?
export const removeOverride = async (req, res, next) => {
  try {
    const target = req.params.id || req.query.url || req.body?.url;
    const policy = await getOrCreateUserPolicy(req.user._id);
    const cleanTarget = String(target || '').toLowerCase().trim();

    const initialLen = (policy.overrides || []).length;
    policy.overrides = (policy.overrides || []).filter(
      (item) =>
        item._id?.toString() !== req.params.id &&
        item.normalizedUrl !== cleanTarget &&
        item.url.toLowerCase().trim() !== cleanTarget
    );

    if (policy.overrides.length === initialLen) {
      return errorResponse(res, 404, 'Override entry not found.');
    }

    await policy.save();
    return successResponse(res, 200, 'Override removed successfully.', policy.overrides);
  } catch (error) {
    next(error);
  }
};

