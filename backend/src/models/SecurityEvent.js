import mongoose from 'mongoose';
import {
  RISK_LEVELS,
  PROTECTION_MODES,
  PROTECTION_RECOMMENDATIONS,
  PROTECTION_ACTIONS,
  USER_DECISIONS,
  SECURITY_EVENT_SOURCES
} from '../config/constants.js';

const securityEventSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    url: {
      type: String,
      required: true,
      trim: true
    },
    normalizedUrl: {
      type: String,
      required: true,
      trim: true
    },
    domain: {
      type: String,
      default: '',
      trim: true,
      lowercase: true
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
    recommendation: {
      type: String,
      enum: Object.values(PROTECTION_RECOMMENDATIONS),
      required: true
    },
    action: {
      type: String,
      enum: Object.values(PROTECTION_ACTIONS),
      required: true
    },
    policyMode: {
      type: String,
      enum: Object.values(PROTECTION_MODES),
      required: true
    },
    userDecision: {
      type: String,
      enum: [...Object.values(USER_DECISIONS), null],
      default: null
    },
    source: {
      type: String,
      enum: Object.values(SECURITY_EVENT_SOURCES),
      default: 'WEB'
    },
    reasonCodes: {
      type: [String],
      default: []
    },
    analysisVersion: {
      type: String,
      default: '3.0.0'
    }
  },
  {
    timestamps: { createdAt: true, updatedAt: false } // Append-only audit log
  }
);

// Compound indexes for user-isolated queries and reporting
securityEventSchema.index({ user: 1, createdAt: -1 });
securityEventSchema.index({ user: 1, action: 1 });
securityEventSchema.index({ user: 1, riskLevel: 1 });

securityEventSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.__v;
  return obj;
};

export const SecurityEvent = mongoose.model('SecurityEvent', securityEventSchema);
