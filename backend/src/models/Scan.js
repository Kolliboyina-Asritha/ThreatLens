import mongoose from 'mongoose';
import { RISK_LEVELS, INDICATOR_SEVERITY } from '../config/constants.js';

const indicatorSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      required: true
    },
    severity: {
      type: String,
      enum: Object.values(INDICATOR_SEVERITY),
      required: true
    },
    score: {
      type: Number,
      required: true
    },
    message: {
      type: String,
      required: true
    },
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  },
  { _id: false }
);

const timelineStepSchema = new mongoose.Schema(
  {
    stage: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    status: { type: String, enum: ['COMPLETED', 'SKIPPED', 'DEGRADED', 'FAILED'], default: 'COMPLETED' },
    durationMs: { type: Number, default: 0 },
    detail: { type: String, default: '' }
  },
  { _id: false }
);

const scanSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    originalUrl: {
      type: String,
      required: true,
      trim: true
    },
    normalizedUrl: {
      type: String,
      required: true,
      trim: true
    },
    features: {
      type: mongoose.Schema.Types.Mixed,
      required: true
    },
    indicators: {
      type: [indicatorSchema],
      default: []
    },
    riskScore: {
      type: Number,
      required: true,
      min: 0,
      max: 100
    },
    riskLevel: {
      type: String,
      enum: Object.values(RISK_LEVELS),
      required: true
    },

    // Phase 2 Intelligence Fields
    ml: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },
    threatIntelligence: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },
    riskBreakdown: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },
    aiExplanation: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },
    investigationTimeline: {
      type: [timelineStepSchema],
      default: []
    },
    analysisVersion: {
      type: String,
      default: '2.0.0'
    }
  },
  {
    timestamps: true
  }
);

// Compound index for user query pagination
scanSchema.index({ user: 1, createdAt: -1 });

// Sanitize scan object output
scanSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.__v;
  return obj;
};

export const Scan = mongoose.model('Scan', scanSchema);
