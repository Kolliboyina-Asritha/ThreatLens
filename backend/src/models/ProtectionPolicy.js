import mongoose from 'mongoose';
import { PROTECTION_MODES } from '../config/constants.js';

const listEntrySchema = new mongoose.Schema(
  {
    value: {
      type: String,
      required: true,
      trim: true,
      lowercase: true
    },
    type: {
      type: String,
      enum: ['DOMAIN', 'URL'],
      default: 'DOMAIN'
    },
    addedAt: {
      type: Date,
      default: Date.now
    }
  },
  { _id: true }
);

const overrideEntrySchema = new mongoose.Schema(
  {
    url: {
      type: String,
      required: true,
      trim: true
    },
    normalizedUrl: {
      type: String,
      required: true,
      trim: true,
      lowercase: true
    },
    action: {
      type: String,
      enum: ['ALLOW', 'BLOCK'],
      default: 'ALLOW'
    },
    userDecision: {
      type: String,
      default: 'OVERRIDE'
    },
    reason: {
      type: String,
      default: 'User explicit override'
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  },
  { _id: true }
);

const protectionPolicySchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      unique: true,
      index: true
    },
    mode: {
      type: String,
      enum: Object.values(PROTECTION_MODES || {
        ASK_ME: 'ASK_ME',
        BALANCED: 'BALANCED',
        STRICT: 'STRICT',
        CUSTOM: 'CUSTOM'
      }),
      default: 'ASK_ME'
    },
    customThresholds: {
      allowMax: {
        type: Number,
        default: 29,
        min: 0,
        max: 99
      },
      warnMax: {
        type: Number,
        default: 69,
        min: 1,
        max: 100
      }
    },
    allowlist: {
      type: [listEntrySchema],
      default: []
    },
    blocklist: {
      type: [listEntrySchema],
      default: []
    },
    overrides: {
      type: [overrideEntrySchema],
      default: []
    }
  },
  {
    timestamps: true
  }
);

// Validate that custom allowMax is strictly less than warnMax
protectionPolicySchema.pre('validate', function (next) {
  if (this.customThresholds) {
    const { allowMax, warnMax } = this.customThresholds;
    if (typeof allowMax === 'number' && typeof warnMax === 'number' && allowMax >= warnMax) {
      return next(new Error('customThresholds.allowMax must be strictly less than customThresholds.warnMax'));
    }
  }
  next();
});

// Sanitize output
protectionPolicySchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.__v;
  return obj;
};

export const ProtectionPolicy = mongoose.model('ProtectionPolicy', protectionPolicySchema);
