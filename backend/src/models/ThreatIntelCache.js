import mongoose from 'mongoose';
import { SERVICE_CONFIG } from '../config/constants.js';

const threatIntelCacheSchema = new mongoose.Schema(
  {
    urlHash: {
      type: String,
      required: true,
      unique: true,
      index: true
    },
    normalizedUrl: {
      type: String,
      required: true,
      trim: true
    },
    provider: {
      type: String,
      required: true,
      default: 'VirusTotal'
    },
    result: {
      type: mongoose.Schema.Types.Mixed,
      required: true
    },
    fetchedAt: {
      type: Date,
      default: Date.now
    },
    expiresAt: {
      type: Date,
      required: true,
      // MongoDB TTL index: automatically deletes document when expiresAt timestamp is reached
      index: { expires: 0 }
    }
  },
  {
    timestamps: true
  }
);

// Helper method to create expiration date based on configured TTL
threatIntelCacheSchema.statics.calculateExpiry = function () {
  const ttlMs = SERVICE_CONFIG.TI_CACHE_TTL_HOURS * 60 * 60 * 1000;
  return new Date(Date.now() + ttlMs);
};

export const ThreatIntelCache = mongoose.model('ThreatIntelCache', threatIntelCacheSchema);
