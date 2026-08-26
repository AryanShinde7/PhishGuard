/**
 * models/Detection.js — PhishGuard Detection Schema (Mongoose)
 *
 * Stores the result of each URL + DOM analysis evaluation.
 * Phase 7: MongoDB connection will activate this model.
 */

const mongoose = require('mongoose');

const DetectionSchema = new mongoose.Schema(
  {
    url: {
      type: String,
      required: [true, 'URL is required'],
      trim: true,
      maxlength: [2048, 'URL must be under 2048 characters']
    },
    domain: {
      type: String,
      required: true,
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
      required: true,
      enum: ['SAFE', 'SUSPICIOUS', 'HIGH RISK'],
      uppercase: true
    },
    urlFlags: {
      type: [String],
      default: []
    },
    domFlags: {
      type: [String],
      default: []
    },
    reasons: {
      type: [String],
      default: []
    },
    features: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },
    source: {
      type: String,
      enum: ['extension', 'api'],
      default: 'extension'
    }
  },
  {
    timestamps: true   // Adds createdAt and updatedAt automatically
  }
);

// Index for fast domain-based queries
DetectionSchema.index({ domain: 1, createdAt: -1 });
DetectionSchema.index({ riskLevel: 1 });

module.exports = mongoose.model('Detection', DetectionSchema);
