import mongoose from 'mongoose';
import { Scan } from '../models/Scan.js';
import { scanUrlSchema, paginationSchema } from '../validators/scanValidators.js';
import { extractUrlFeatures } from '../services/urlAnalyzer.js';
import { evaluateHeuristics } from '../services/heuristicEngine.js';
import { predictThreatWithML } from '../services/mlService.js';
import { getThreatIntelligence } from '../services/threatIntelService.js';
import { fuseRiskEvidence } from '../services/riskFusionEngine.js';
import { explainThreatEvidence } from '../services/llmService.js';
import { successResponse, errorResponse } from '../utils/apiResponse.js';

export const scanUrl = async (req, res, next) => {
  try {
    const { url } = scanUrlSchema.parse(req.body);
    const timeline = [];

    // Stage 1 & 2: Normalization and Feature Extraction (SSRF-Safe)
    const t0 = Date.now();
    const features = extractUrlFeatures(url);
    const featureDuration = Date.now() - t0;
    timeline.push({
      stage: 'FEATURE_EXTRACTION',
      timestamp: new Date(),
      status: 'COMPLETED',
      durationMs: featureDuration,
      detail: `Extracted ${Object.keys(features).length} structural and security features.`
    });

    // Stage 3: Modular 9-Rule Heuristic Engine
    const t1 = Date.now();
    const indicators = evaluateHeuristics(features);
    const heurDuration = Date.now() - t1;
    timeline.push({
      stage: 'HEURISTIC_ANALYSIS',
      timestamp: new Date(),
      status: 'COMPLETED',
      durationMs: heurDuration,
      detail: `Evaluated 9 heuristic rules; flagged ${indicators.length} indicators.`
    });

    // Stage 4 & 5: Parallel Machine Learning Inference & Threat Intelligence Telemetry
    const t2 = Date.now();
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

    const mlTiDuration = Date.now() - t2;

    timeline.push({
      stage: 'ML_CLASSIFICATION',
      timestamp: new Date(),
      status: mlResult.available ? 'COMPLETED' : 'DEGRADED',
      durationMs: Math.round(mlTiDuration / 2),
      detail: mlResult.available
        ? `Random Forest prediction: ${mlResult.prediction} (Probability: ${Math.round((mlResult.probability || 0) * 100)}%)`
        : `ML classification degraded: ${mlResult.error || 'Unavailable'}`
    });

    timeline.push({
      stage: 'THREAT_INTELLIGENCE',
      timestamp: new Date(),
      status: tiResult.available ? 'COMPLETED' : 'DEGRADED',
      durationMs: Math.round(mlTiDuration / 2),
      detail: tiResult.available
        ? `VirusTotal lookup: ${tiResult.malicious} malicious detections (Score: ${tiResult.score}/100, cached: ${Boolean(tiResult.cached)})`
        : `Threat Intelligence degraded: ${tiResult.error || 'Unavailable'}`
    });

    // Stage 6: Unified Multi-Engine Risk Fusion
    const t3 = Date.now();
    const { riskScore, riskLevel, riskBreakdown } = fuseRiskEvidence({
      indicators,
      ml: mlResult,
      threatIntelligence: tiResult
    });
    const fusionDuration = Date.now() - t3;
    timeline.push({
      stage: 'RISK_FUSION',
      timestamp: new Date(),
      status: 'COMPLETED',
      durationMs: fusionDuration,
      detail: `Fused active engines [${riskBreakdown.activeEngines.join(', ')}] -> Risk Score: ${riskScore} (${riskLevel})`
    });

    // Stage 7: Generative AI / LLM Plain-Language Explanation
    const t4 = Date.now();
    const aiExplanation = await explainThreatEvidence({
      url: features.originalUrl,
      riskScore,
      riskLevel,
      indicators,
      ml: mlResult,
      threatIntelligence: tiResult,
      features
    });
    const llmDuration = Date.now() - t4;
    timeline.push({
      stage: 'LLM_EXPLANATION',
      timestamp: new Date(),
      status: 'COMPLETED',
      durationMs: llmDuration,
      detail: `Generated human-readable explanation via ${aiExplanation.source || 'ThreatLens Engine'}.`
    });

    // Stage 8: Persist Scan Record in MongoDB under authenticated user
    const scan = await Scan.create({
      user: req.user._id,
      originalUrl: features.originalUrl,
      normalizedUrl: features.normalizedUrl,
      features,
      indicators,
      riskScore,
      riskLevel,
      ml: mlResult,
      threatIntelligence: tiResult,
      riskBreakdown,
      aiExplanation,
      investigationTimeline: timeline,
      analysisVersion: '2.0.0'
    });

    return successResponse(
      res,
      201,
      'URL threat analysis completed successfully.',
      {
        scanId: scan._id,
        url: scan.originalUrl,
        originalUrl: scan.originalUrl,
        normalizedUrl: scan.normalizedUrl,
        riskScore: scan.riskScore,
        riskLevel: scan.riskLevel,
        features: {
          protocol: features.protocol,
          hostname: features.hostname,
          isIpAddress: features.isIpAddress,
          isIpv4: features.isIpv4,
          isIpv6: features.isIpv6,
          usesHttps: features.usesHttps,
          usesHttp: features.usesHttp,
          urlLength: features.urlLength,
          hostnameLength: features.hostnameLength,
          pathnameLength: features.pathnameLength,
          queryLength: features.queryLength,
          subdomainCount: features.subdomainCount,
          subdomains: features.subdomains,
          specialCharacterCount: features.specialCharacterCount,
          dotCount: features.dotCount,
          pathSegmentCount: features.pathSegmentCount,
          queryParamsCount: features.queryParamsCount,
          detectedKeywords: features.detectedKeywords,
          percentCount: features.percentCount,
          atSymbolCount: features.atSymbolCount,
          tld: features.tld,
          domain: features.domain
        },
        indicators: scan.indicators,
        ml: scan.ml,
        threatIntelligence: scan.threatIntelligence,
        riskBreakdown: scan.riskBreakdown,
        aiExplanation: scan.aiExplanation,
        investigationTimeline: scan.investigationTimeline,
        analysisVersion: scan.analysisVersion,
        analyzedAt: scan.createdAt
      }
    );
  } catch (error) {
    next(error);
  }
};

export const getScans = async (req, res, next) => {
  try {
    const { page, limit } = paginationSchema.parse(req.query);
    const skip = (page - 1) * limit;

    const query = { user: req.user._id };

    const [scans, totalCount] = await Promise.all([
      Scan.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Scan.countDocuments(query)
    ]);

    const totalPages = Math.ceil(totalCount / limit);

    return successResponse(
      res,
      200,
      'Scan history retrieved successfully.',
      scans.map((s) => ({
        id: s._id,
        originalUrl: s.originalUrl,
        normalizedUrl: s.normalizedUrl,
        riskScore: s.riskScore,
        riskLevel: s.riskLevel,
        indicatorCount: s.indicators ? s.indicators.length : 0,
        mlPrediction: s.ml?.prediction || null,
        mlProbability: s.ml?.probability ?? null,
        threatIntelScore: s.threatIntelligence?.score ?? null,
        createdAt: s.createdAt
      })),
      {
        page,
        limit,
        totalCount,
        totalPages,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1
      }
    );
  } catch (error) {
    next(error);
  }
};

export const getScanById = async (req, res, next) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return errorResponse(res, 404, 'Scan record not found.');
    }

    // Strictly enforce scan isolation: query must match both ID and user ID
    const scan = await Scan.findOne({
      _id: id,
      user: req.user._id
    }).lean();

    if (!scan) {
      return errorResponse(res, 404, 'Scan record not found.');
    }

    return successResponse(res, 200, 'Scan details retrieved successfully.', {
      scanId: scan._id,
      url: scan.originalUrl,
      originalUrl: scan.originalUrl,
      normalizedUrl: scan.normalizedUrl,
      riskScore: scan.riskScore,
      riskLevel: scan.riskLevel,
      features: scan.features,
      indicators: scan.indicators,
      ml: scan.ml,
      threatIntelligence: scan.threatIntelligence,
      riskBreakdown: scan.riskBreakdown,
      aiExplanation: scan.aiExplanation,
      investigationTimeline: scan.investigationTimeline || [],
      analysisVersion: scan.analysisVersion || '1.0.0',
      analyzedAt: scan.createdAt
    });
  } catch (error) {
    next(error);
  }
};

export const deleteScan = async (req, res, next) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return errorResponse(res, 404, 'Scan record not found.');
    }

    // Strictly enforce scan isolation on deletion
    const deleted = await Scan.findOneAndDelete({
      _id: id,
      user: req.user._id
    });

    if (!deleted) {
      return errorResponse(res, 404, 'Scan record not found.');
    }

    return successResponse(res, 200, 'Scan record deleted successfully.', {
      id: deleted._id
    });
  } catch (error) {
    next(error);
  }
};
