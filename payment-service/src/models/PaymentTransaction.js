/**
 * Payment Transaction Model
 * Stores all payment attempts, successful and failed transactions
 * Provides audit trail and compliance logging
 */

const mongoose = require("mongoose");

const paymentTransactionSchema = new mongoose.Schema(
  {
    // Transaction Identification
    transactionId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    stripeSessionId: {
      type: String,
      required: false,
      index: true,
    },
    stripePaymentIntentId: {
      type: String,
      required: false,
      index: true,
    },

    // User Information
    userId: {
      type: String,
      required: true,
      index: true,
    },
    userEmail: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
    },
    userRole: {
      type: String,
      required: true,
      enum: ["customer", "admin", "restaurant_owner"],
    },

    // Payment Details
    items: [
      {
        name: {
          type: String,
          required: true,
          trim: true,
          maxlength: 100,
        },
        price: {
          type: Number,
          required: true,
          min: 0.01,
          max: 10000,
        },
        quantity: {
          type: Number,
          required: true,
          min: 1,
          max: 100,
        },
        imageUrl: {
          type: String,
          required: false,
          validate: {
            validator: function (v) {
              if (!v) return true; // Optional field
              return /^https?:\/\/.+/.test(v);
            },
            message: "Image URL must be a valid HTTP/HTTPS URL",
          },
        },
        itemId: {
          type: String,
          required: false,
          validate: {
            validator: function (v) {
              if (!v) return true; // Optional field
              return /^[0-9a-fA-F]{24}$/.test(v);
            },
            message: "Item ID must be a valid MongoDB ObjectId",
          },
        },
        description: {
          type: String,
          required: false,
          trim: true,
          maxlength: 500,
        },
        category: {
          type: String,
          required: false,
          trim: true,
          lowercase: true,
          enum: [
            "appetizer",
            "main",
            "dessert",
            "beverage",
            "salad",
            "soup",
            "pizza",
            "burger",
            "pasta",
            "rice",
            "general",
          ],
          default: "general",
        },
      },
    ],

    // Financial Information
    totalAmount: {
      type: Number,
      required: true,
      min: 0.01,
      max: 100000,
    },
    currency: {
      type: String,
      required: true,
      default: "LKR",
      enum: ["LKR", "USD", "EUR"],
    },
    taxAmount: {
      type: Number,
      required: false,
      min: 0,
      default: 0,
    },
    discountAmount: {
      type: Number,
      required: false,
      min: 0,
      default: 0,
    },

    // Transaction Status
    status: {
      type: String,
      required: true,
      enum: [
        "pending", // Payment initiated
        "processing", // Being processed by Stripe
        "succeeded", // Payment successful
        "failed", // Payment failed
        "cancelled", // User cancelled
        "refunded", // Payment refunded
        "fraud_detected", // Blocked by fraud detection
        "validation_failed", // Failed validation
        "rate_limited", // Blocked by rate limiting
      ],
      default: "pending",
    },

    // Fraud Detection
    fraudDetection: {
      riskScore: {
        type: Number,
        required: false,
        min: 0,
        max: 1000,
      },
      isSuspicious: {
        type: Boolean,
        required: false,
        default: false,
      },
      fraudIndicators: [
        {
          type: {
            type: String,
            required: true,
          },
          severity: {
            type: String,
            required: true,
            enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
          },
          message: {
            type: String,
            required: true,
          },
          details: {
            type: mongoose.Schema.Types.Mixed,
            required: false,
          },
        },
      ],
      recommendation: {
        type: String,
        required: false,
        enum: ["ALLOW", "MONITOR", "REVIEW", "BLOCK"],
      },
    },

    // Technical Information
    requestMetadata: {
      ipAddress: {
        type: String,
        required: true,
      },
      userAgent: {
        type: String,
        required: true,
        maxlength: 500,
      },
      requestId: {
        type: String,
        required: false,
      },
      sessionId: {
        type: String,
        required: false,
      },
    },

    // Stripe Information
    stripeData: {
      sessionUrl: {
        type: String,
        required: false,
      },
      paymentMethod: {
        type: String,
        required: false,
      },
      paymentStatus: {
        type: String,
        required: false,
      },
      failureReason: {
        type: String,
        required: false,
      },
      refundId: {
        type: String,
        required: false,
      },
      refundAmount: {
        type: Number,
        required: false,
        min: 0,
      },
    },

    // Error Information
    errorDetails: {
      code: {
        type: String,
        required: false,
      },
      message: {
        type: String,
        required: false,
        maxlength: 1000,
      },
      stack: {
        type: String,
        required: false,
      },
      timestamp: {
        type: Date,
        required: false,
      },
    },

    // Timestamps
    createdAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
    completedAt: {
      type: Date,
      required: false,
    },
    failedAt: {
      type: Date,
      required: false,
    },

    // Additional Metadata
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      required: false,
    },
  },
  {
    timestamps: true,
    collection: "payment_transactions",
  }
);

// Indexes for performance
paymentTransactionSchema.index({ userId: 1, createdAt: -1 });
paymentTransactionSchema.index({ status: 1, createdAt: -1 });
paymentTransactionSchema.index({ "fraudDetection.isSuspicious": 1 });
paymentTransactionSchema.index({ totalAmount: 1, createdAt: -1 });
paymentTransactionSchema.index({ "requestMetadata.ipAddress": 1 });

// Pre-save middleware
paymentTransactionSchema.pre("save", function (next) {
  this.updatedAt = new Date();

  // Set completion timestamps based on status
  if (this.status === "succeeded" && !this.completedAt) {
    this.completedAt = new Date();
  }

  if (
    [
      "failed",
      "cancelled",
      "fraud_detected",
      "validation_failed",
      "rate_limited",
    ].includes(this.status) &&
    !this.failedAt
  ) {
    this.failedAt = new Date();
  }

  next();
});

// Instance methods
paymentTransactionSchema.methods.markAsCompleted = function (stripeData = {}) {
  this.status = "succeeded";
  this.completedAt = new Date();
  this.stripeData = { ...this.stripeData, ...stripeData };
  return this.save();
};

paymentTransactionSchema.methods.markAsFailed = function (errorDetails = {}) {
  this.status = "failed";
  this.failedAt = new Date();
  this.errorDetails = { ...this.errorDetails, ...errorDetails };
  return this.save();
};

paymentTransactionSchema.methods.markAsFraud = function (fraudData) {
  this.status = "fraud_detected";
  this.failedAt = new Date();
  this.fraudDetection = { ...this.fraudDetection, ...fraudData };
  return this.save();
};

paymentTransactionSchema.methods.markAsValidationFailed = function (
  errorDetails = {}
) {
  this.status = "validation_failed";
  this.failedAt = new Date();
  this.errorDetails = { ...this.errorDetails, ...errorDetails };
  return this.save();
};

paymentTransactionSchema.methods.markAsRateLimited = function () {
  this.status = "rate_limited";
  this.failedAt = new Date();
  return this.save();
};

// Static methods
paymentTransactionSchema.statics.findByUserId = function (
  userId,
  limit = 50,
  skip = 0
) {
  return this.find({ userId }).sort({ createdAt: -1 }).limit(limit).skip(skip);
};

paymentTransactionSchema.statics.findSuspiciousTransactions = function (
  limit = 100
) {
  return this.find({ "fraudDetection.isSuspicious": true })
    .sort({ createdAt: -1 })
    .limit(limit);
};

paymentTransactionSchema.statics.getTransactionStats = function (
  userId,
  startDate,
  endDate
) {
  const matchStage = { userId };

  if (startDate && endDate) {
    matchStage.createdAt = {
      $gte: new Date(startDate),
      $lte: new Date(endDate),
    };
  }

  return this.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: "$status",
        count: { $sum: 1 },
        totalAmount: { $sum: "$totalAmount" },
        avgAmount: { $avg: "$totalAmount" },
      },
    },
  ]);
};

// Virtual fields
paymentTransactionSchema.virtual("isSuccessful").get(function () {
  return this.status === "succeeded";
});

paymentTransactionSchema.virtual("isFailed").get(function () {
  return [
    "failed",
    "cancelled",
    "fraud_detected",
    "validation_failed",
    "rate_limited",
  ].includes(this.status);
});

paymentTransactionSchema.virtual("isPending").get(function () {
  return ["pending", "processing"].includes(this.status);
});

paymentTransactionSchema.virtual("duration").get(function () {
  if (this.completedAt && this.createdAt) {
    return this.completedAt.getTime() - this.createdAt.getTime();
  }
  if (this.failedAt && this.createdAt) {
    return this.failedAt.getTime() - this.createdAt.getTime();
  }
  return null;
});

// Ensure virtual fields are included in JSON output
paymentTransactionSchema.set("toJSON", { virtuals: true });
paymentTransactionSchema.set("toObject", { virtuals: true });

module.exports = mongoose.model("PaymentTransaction", paymentTransactionSchema);
