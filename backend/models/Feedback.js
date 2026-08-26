/**
 * models/Feedback.js — PhishGuard User Feedback Schema (Mongoose)
 *
 * Stores user-submitted reports and feedback about detected pages.
 * Used for model improvement and community threat intelligence.
 */

const mongoose = require('mongoose');

const FeedbackSchema = new mongoose.Schema(
  {
    url: {
      type: String,
      required: [true, 'URL is required'],
      trim: true
    },
    domain: {
      type: String,
      required: true,
      trim: true,
      lowercase: true
    },
    feedbackType: {
      type: String,
      required: true,
      enum: ['suspicious', 'safe', 'false_positive', 'false_negative'],
    },
    riskScore: {
      type: Number,
      min: 0,
      max: 100,
      default: null
    },
    riskLevel: {
      type: String,
      enum: ['SAFE', 'SUSPICIOUS', 'HIGH RISK', null],
      default: null
    },
    comment: {
      type: String,
      trim: true,
      maxlength: [500, 'Comment must be under 500 characters'],
      default: ''
    },
    detectionRef: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Detection',
      default: null
    }
  },
  {
    timestamps: true
  }
);

FeedbackSchema.index({ domain: 1, feedbackType: 1 });

module.exports = mongoose.model('Feedback', FeedbackSchema);
