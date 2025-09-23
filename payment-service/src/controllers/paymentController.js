const Stripe = require("stripe");
const PaymentValidator = require("../validators/paymentValidator");
const FraudDetection = require("../middleware/fraudDetection");
const PaymentLogger = require("../services/paymentLogger");
const {
  checkoutLimiter,
  suspiciousActivityLimiter,
} = require("../middleware/rateLimiter");

// Initialize Stripe
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// Initialize validator, fraud detection, and logger
const paymentValidator = new PaymentValidator();
const fraudDetection = new FraudDetection();
const paymentLogger = new PaymentLogger();

/**
 * Create secure checkout session with comprehensive validation
 */
exports.createCheckoutSession = [
  checkoutLimiter,
  async (req, res) => {
    let transaction = null;

    try {
      // Extract user information from headers
      const userId = req.headers["x-user-id"];
      const userRole = req.headers["x-user-role"];
      const userEmail = req.headers["x-user-email"];

      // Validate required headers
      if (!userId) {
        return res.status(401).json({
          error: "User authentication required",
          code: "MISSING_USER_ID",
        });
      }

      // Validate and sanitize payment data
      let validatedData;
      try {
        validatedData = paymentValidator.validatePaymentItems(req.body);
      } catch (validationError) {
        // Log validation failure
        try {
          await paymentLogger.logPaymentFailure(
            null, // No transaction ID yet
            {
              code: "VALIDATION_ERROR",
              message: validationError.message,
              timestamp: new Date().toISOString(),
            },
            "validation_failed"
          );
        } catch (logError) {
          console.error("Failed to log validation failure:", logError);
        }

        return res.status(400).json({
          error: validationError.message,
          code: "VALIDATION_ERROR",
        });
      }

      // Simulate user history (in real app, fetch from database)
      const userHistory = {
        recentPayments: 0, // Would be fetched from database
        avgOrderValue: 1500, // Would be calculated from user's order history
        totalOrders: 5, // Would be fetched from database
      };

      // Fraud detection
      const fraudResult = fraudDetection.detectFraud(
        req,
        validatedData,
        userHistory
      );

      // Log fraud detection results
      fraudDetection.logFraudDetection(fraudResult, req, validatedData);

      // Log payment attempt
      try {
        transaction = await paymentLogger.logPaymentAttempt(
          validatedData,
          { userId, userEmail, userRole },
          {
            ipAddress: req.ip,
            userAgent: req.headers["user-agent"],
            requestId: req.headers["x-request-id"],
            sessionId: req.headers["x-session-id"],
          },
          fraudResult
        );
      } catch (logError) {
        console.error("Failed to log payment attempt:", logError);
        // Continue processing even if logging fails
      }

      // Handle fraud detection results
      if (fraudResult.isFraudulent) {
        // Log fraud detection
        if (transaction) {
          try {
            await paymentLogger.logPaymentFailure(
              transaction.transactionId,
              {
                code: "FRAUD_DETECTED",
                message: "Transaction blocked due to suspicious activity",
                riskScore: fraudResult.riskScore,
                fraudIndicators: fraudResult.fraudIndicators,
                timestamp: new Date().toISOString(),
              },
              "fraud_detected"
            );
          } catch (logError) {
            console.error("Failed to log fraud detection:", logError);
          }
        }

        return res.status(403).json({
          error: "Transaction blocked due to suspicious activity",
          code: "FRAUD_DETECTED",
          riskScore: fraudResult.riskScore,
          recommendation: fraudResult.recommendation,
          transactionId: transaction?.transactionId,
        });
      }

      // Apply additional rate limiting for suspicious activity
      if (fraudResult.isSuspicious) {
        // Apply stricter rate limiting
        return suspiciousActivityLimiter(req, res, () => {
          processSuspiciousPayment(
            req,
            res,
            validatedData,
            fraudResult,
            transaction
          );
        });
      }

      // Process normal payment
      await processNormalPayment(
        req,
        res,
        validatedData,
        userId,
        userEmail,
        transaction
      );
    } catch (error) {
      console.error("Payment processing error:", error);

      // Log payment failure
      if (transaction) {
        try {
          await paymentLogger.logPaymentFailure(
            transaction.transactionId,
            {
              code: "PAYMENT_PROCESSING_ERROR",
              message: error.message,
              stack: error.stack,
              timestamp: new Date().toISOString(),
            },
            "failed"
          );
        } catch (logError) {
          console.error("Failed to log payment failure:", logError);
        }
      }

      // Don't expose internal errors
      const errorMessage =
        error.message.includes("validation") ||
        error.message.includes("fraud") ||
        error.message.includes("rate limit")
          ? error.message
          : "Payment processing failed";

      res.status(500).json({
        error: errorMessage,
        code: "PAYMENT_PROCESSING_ERROR",
        transactionId: transaction?.transactionId,
      });
    }
  },
];

/**
 * Process normal payment (low risk)
 */
async function processNormalPayment(
  req,
  res,
  validatedData,
  userId,
  userEmail,
  transaction
) {
  try {
    // Create Stripe session with validated data
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: validatedData.items.map((item) => ({
        price_data: {
          currency: "lkr",
          product_data: {
            name: item.name,
            description: item.description,
            images: item.imageUrl ? [item.imageUrl] : [],
            metadata: {
              itemId: item.itemId || "",
              category: item.category,
              validated: "true",
            },
          },
          unit_amount: Math.round(item.price * 100), // Convert to cents
        },
        quantity: item.quantity,
      })),
      mode: "payment",
      success_url: `${process.env.FRONTEND_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/cancel`,
      customer_email: userEmail,
      metadata: {
        userId: userId,
        transactionId: transaction?.transactionId,
        totalAmount: validatedData.totalAmount.toString(),
        itemCount: validatedData.itemCount.toString(),
        timestamp: new Date().toISOString(),
        riskScore: "0",
        validationStatus: "passed",
      },
      payment_intent_data: {
        metadata: {
          userId: userId,
          transactionId: transaction?.transactionId,
          source: "cloudkitchen-web",
          validated: "true",
          fraudCheck: "passed",
        },
      },
      // Prevent duplicate sessions
      client_reference_id: `payment_${Date.now()}_${Math.random()
        .toString(36)
        .substr(2, 9)}`,
      // Set expiration
      expires_at: Math.floor(Date.now() / 1000) + 30 * 60, // 30 minutes
      // Configure allowed payment methods
      payment_method_options: {
        card: {
          request_three_d_secure: "automatic",
        },
      },
    });

    // Log successful session creation
    console.log(
      `✅ Payment session created: ${session.id} for user: ${userId}, amount: ${validatedData.totalAmount}`
    );

    // Log successful session creation in database
    if (transaction) {
      try {
        await paymentLogger.logPaymentSuccess(transaction.transactionId, {
          id: session.id,
          url: session.url,
          expires_at: session.expires_at,
        });
      } catch (logError) {
        console.error("Failed to log payment success:", logError);
      }
    }

    res.json({
      id: session.id,
      url: session.url,
      amount: validatedData.totalAmount,
      currency: "LKR",
      expiresAt: session.expires_at,
      transactionId: transaction?.transactionId,
    });
  } catch (stripeError) {
    console.error("Stripe session creation error:", stripeError);

    // Log Stripe failure
    if (transaction) {
      try {
        await paymentLogger.logPaymentFailure(
          transaction.transactionId,
          {
            code: "STRIPE_SESSION_CREATION_FAILED",
            message: stripeError.message,
            stripeErrorType: stripeError.type,
            timestamp: new Date().toISOString(),
          },
          "failed"
        );
      } catch (logError) {
        console.error("Failed to log Stripe failure:", logError);
      }
    }

    // Handle specific Stripe errors
    if (stripeError.type === "StripeCardError") {
      return res.status(400).json({
        error: "Payment method error",
        code: "STRIPE_CARD_ERROR",
        details: stripeError.message,
        transactionId: transaction?.transactionId,
      });
    }

    if (stripeError.type === "StripeRateLimitError") {
      return res.status(429).json({
        error: "Too many requests to payment processor",
        code: "STRIPE_RATE_LIMIT",
        retryAfter: "60 seconds",
      });
    }

    res.status(500).json({
      error: "Payment session creation failed",
      code: "STRIPE_ERROR",
    });
  }
}

/**
 * Process suspicious payment (requires additional verification)
 */
async function processSuspiciousPayment(req, res, validatedData, fraudResult) {
  try {
    // Create session with additional security measures
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: validatedData.items.map((item) => ({
        price_data: {
          currency: "lkr",
          product_data: {
            name: item.name,
            description: item.description,
            images: item.imageUrl ? [item.imageUrl] : [],
            metadata: {
              itemId: item.itemId || "",
              category: item.category,
              validated: "true",
              suspicious: "true",
            },
          },
          unit_amount: Math.round(item.price * 100),
        },
        quantity: item.quantity,
      })),
      mode: "payment",
      success_url: `${process.env.FRONTEND_URL}/success?session_id={CHECKOUT_SESSION_ID}&review=true`,
      cancel_url: `${process.env.FRONTEND_URL}/cancel`,
      metadata: {
        userId: req.headers["x-user-id"],
        totalAmount: validatedData.totalAmount.toString(),
        itemCount: validatedData.itemCount.toString(),
        timestamp: new Date().toISOString(),
        riskScore: fraudResult.riskScore.toString(),
        validationStatus: "suspicious",
        fraudIndicators: JSON.stringify(fraudResult.fraudIndicators),
      },
      payment_intent_data: {
        metadata: {
          userId: req.headers["x-user-id"],
          source: "cloudkitchen-web",
          validated: "true",
          fraudCheck: "suspicious",
          riskScore: fraudResult.riskScore.toString(),
        },
      },
      // Require additional verification
      payment_method_options: {
        card: {
          request_three_d_secure: "any",
        },
      },
      // Shorter expiration for suspicious payments
      expires_at: Math.floor(Date.now() / 1000) + 15 * 60, // 15 minutes
      client_reference_id: `suspicious_payment_${Date.now()}_${Math.random()
        .toString(36)
        .substr(2, 9)}`,
    });

    console.log(
      `⚠️ Suspicious payment session created: ${session.id} for user: ${req.headers["x-user-id"]}, risk score: ${fraudResult.riskScore}`
    );

    res.json({
      id: session.id,
      url: session.url,
      amount: validatedData.totalAmount,
      currency: "LKR",
      expiresAt: session.expires_at,
      requiresReview: true,
      riskScore: fraudResult.riskScore,
    });
  } catch (error) {
    console.error("Suspicious payment processing error:", error);
    res.status(500).json({
      error: "Suspicious payment processing failed",
      code: "SUSPICIOUS_PAYMENT_ERROR",
    });
  }
}

/**
 * Get payment history for a user
 */
exports.getPaymentHistory = async (req, res) => {
  try {
    const userId = req.headers["x-user-id"];
    const userRole = req.headers["x-user-role"];

    // Validate authentication
    if (!userId) {
      return res.status(401).json({
        error: "User authentication required",
        code: "MISSING_USER_ID",
      });
    }

    // Extract query parameters
    const {
      limit = 50,
      skip = 0,
      status = null,
      startDate = null,
      endDate = null,
    } = req.query;

    // Validate limit and skip
    const parsedLimit = Math.min(parseInt(limit) || 50, 100); // Max 100 records
    const parsedSkip = Math.max(parseInt(skip) || 0, 0);

    // Get payment history
    const transactions = await paymentLogger.getUserPaymentHistory(userId, {
      limit: parsedLimit,
      skip: parsedSkip,
      status,
      startDate,
      endDate,
    });

    res.json({
      transactions,
      pagination: {
        limit: parsedLimit,
        skip: parsedSkip,
        count: transactions.length,
      },
      filters: {
        status,
        startDate,
        endDate,
      },
    });
  } catch (error) {
    console.error("Payment history retrieval error:", error);

    res.status(500).json({
      error: "Failed to retrieve payment history",
      code: "PAYMENT_HISTORY_ERROR",
    });
  }
};

/**
 * Get payment statistics for a user
 */
exports.getPaymentStats = async (req, res) => {
  try {
    const userId = req.headers["x-user-id"];

    // Validate authentication
    if (!userId) {
      return res.status(401).json({
        error: "User authentication required",
        code: "MISSING_USER_ID",
      });
    }

    // Extract query parameters
    const { startDate = null, endDate = null } = req.query;

    // Get payment statistics
    const stats = await paymentLogger.getUserPaymentStats(userId, {
      startDate,
      endDate,
    });

    res.json(stats);
  } catch (error) {
    console.error("Payment statistics retrieval error:", error);

    res.status(500).json({
      error: "Failed to retrieve payment statistics",
      code: "PAYMENT_STATS_ERROR",
    });
  }
};

/**
 * Get transaction details by ID
 */
exports.getTransactionDetails = async (req, res) => {
  try {
    const { transactionId } = req.params;
    const userId = req.headers["x-user-id"];

    // Validate authentication
    if (!userId) {
      return res.status(401).json({
        error: "User authentication required",
        code: "MISSING_USER_ID",
      });
    }

    // Validate transaction ID
    if (!transactionId) {
      return res.status(400).json({
        error: "Transaction ID is required",
        code: "MISSING_TRANSACTION_ID",
      });
    }

    // Get transaction details
    const transaction = await paymentLogger.getTransactionById(transactionId);

    // Check if user owns this transaction
    if (transaction.userId !== userId) {
      return res.status(403).json({
        error: "Access denied to this transaction",
        code: "TRANSACTION_ACCESS_DENIED",
      });
    }

    res.json(transaction);
  } catch (error) {
    console.error("Transaction details retrieval error:", error);

    if (error.message.includes("not found")) {
      return res.status(404).json({
        error: "Transaction not found",
        code: "TRANSACTION_NOT_FOUND",
      });
    }

    res.status(500).json({
      error: "Failed to retrieve transaction details",
      code: "TRANSACTION_DETAILS_ERROR",
    });
  }
};

/**
 * Get payment session status
 */
exports.getSessionStatus = async (req, res) => {
  try {
    const { sessionId } = req.params;

    if (!sessionId) {
      return res.status(400).json({
        error: "Session ID is required",
        code: "MISSING_SESSION_ID",
      });
    }

    const session = await stripe.checkout.sessions.retrieve(sessionId);

    res.json({
      id: session.id,
      status: session.payment_status,
      amount: session.amount_total,
      currency: session.currency,
      customerEmail: session.customer_email,
      metadata: session.metadata,
    });
  } catch (error) {
    console.error("Session status retrieval error:", error);
    res.status(500).json({
      error: "Failed to retrieve session status",
      code: "SESSION_RETRIEVAL_ERROR",
    });
  }
};
