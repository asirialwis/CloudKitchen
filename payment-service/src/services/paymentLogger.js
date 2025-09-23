/**
 * Payment Logging Service
 * Handles all payment transaction logging and storage
 * Provides comprehensive audit trail for compliance
 */

const PaymentTransaction = require("../models/PaymentTransaction");
const { v4: uuidv4 } = require("uuid");

class PaymentLogger {
  constructor() {
    this.logLevel = process.env.LOG_LEVEL || "info";
  }

  /**
   * Log a new payment transaction attempt
   * @param {Object} paymentData - Payment data
   * @param {Object} userInfo - User information
   * @param {Object} requestInfo - Request metadata
   * @param {Object} fraudResult - Fraud detection result
   * @returns {Promise<Object>} - Created transaction record
   */
  async logPaymentAttempt(
    paymentData,
    userInfo,
    requestInfo,
    fraudResult = null
  ) {
    try {
      const transactionId = uuidv4();

      const transactionData = {
        transactionId,
        userId: userInfo.userId,
        userEmail: userInfo.userEmail,
        userRole: userInfo.userRole,
        items: paymentData.items,
        totalAmount: paymentData.totalAmount,
        currency: paymentData.currency || "LKR",
        status: "pending",
        requestMetadata: {
          ipAddress: requestInfo.ipAddress,
          userAgent: requestInfo.userAgent,
          requestId: requestInfo.requestId,
          sessionId: requestInfo.sessionId,
        },
        metadata: {
          itemCount: paymentData.itemCount,
          validationPassed: true,
          timestamp: new Date().toISOString(),
        },
      };

      // Add fraud detection data if available
      if (fraudResult) {
        transactionData.fraudDetection = {
          riskScore: fraudResult.riskScore,
          isSuspicious: fraudResult.isSuspicious,
          fraudIndicators: fraudResult.fraudIndicators || [],
          recommendation: fraudResult.recommendation,
        };

        // Set status based on fraud detection
        if (fraudResult.isFraudulent) {
          transactionData.status = "fraud_detected";
        } else if (fraudResult.isSuspicious) {
          transactionData.status = "processing"; // Will be reviewed
        }
      }

      const transaction = new PaymentTransaction(transactionData);
      await transaction.save();

      this.logInfo("Payment attempt logged", {
        transactionId,
        userId: userInfo.userId,
        status: transactionData.status,
        amount: paymentData.totalAmount,
      });

      return transaction;
    } catch (error) {
      this.logError("Failed to log payment attempt", error);
      throw new Error("Payment logging failed");
    }
  }

  /**
   * Log successful payment completion
   * @param {string} transactionId - Transaction ID
   * @param {Object} stripeData - Stripe session data
   * @returns {Promise<Object>} - Updated transaction record
   */
  async logPaymentSuccess(transactionId, stripeData) {
    try {
      const transaction = await PaymentTransaction.findOne({ transactionId });

      if (!transaction) {
        throw new Error(`Transaction not found: ${transactionId}`);
      }

      await transaction.markAsCompleted({
        sessionUrl: stripeData.url,
        paymentMethod: stripeData.payment_method_types?.[0],
        paymentStatus: "succeeded",
      });

      this.logInfo("Payment success logged", {
        transactionId,
        userId: transaction.userId,
        amount: transaction.totalAmount,
        stripeSessionId: stripeData.id,
      });

      return transaction;
    } catch (error) {
      this.logError("Failed to log payment success", error);
      throw new Error("Payment success logging failed");
    }
  }

  /**
   * Log payment failure
   * @param {string} transactionId - Transaction ID
   * @param {Object} errorDetails - Error information
   * @param {string} failureType - Type of failure
   * @returns {Promise<Object>} - Updated transaction record
   */
  async logPaymentFailure(transactionId, errorDetails, failureType = "failed") {
    try {
      const transaction = await PaymentTransaction.findOne({ transactionId });

      if (!transaction) {
        throw new Error(`Transaction not found: ${transactionId}`);
      }

      // Update status based on failure type
      if (failureType === "validation_failed") {
        await transaction.markAsValidationFailed(errorDetails);
      } else if (failureType === "rate_limited") {
        await transaction.markAsRateLimited();
      } else if (failureType === "fraud_detected") {
        await transaction.markAsFraud(errorDetails);
      } else {
        await transaction.markAsFailed(errorDetails);
      }

      this.logWarn("Payment failure logged", {
        transactionId,
        userId: transaction.userId,
        status: transaction.status,
        errorCode: errorDetails.code,
        failureType,
      });

      return transaction;
    } catch (error) {
      this.logError("Failed to log payment failure", error);
      throw new Error("Payment failure logging failed");
    }
  }

  /**
   * Log payment cancellation
   * @param {string} transactionId - Transaction ID
   * @param {Object} cancellationData - Cancellation details
   * @returns {Promise<Object>} - Updated transaction record
   */
  async logPaymentCancellation(transactionId, cancellationData = {}) {
    try {
      const transaction = await PaymentTransaction.findOne({ transactionId });

      if (!transaction) {
        throw new Error(`Transaction not found: ${transactionId}`);
      }

      transaction.status = "cancelled";
      transaction.failedAt = new Date();
      transaction.metadata = {
        ...transaction.metadata,
        cancellationReason: cancellationData.reason || "user_cancelled",
        cancellationTimestamp: new Date().toISOString(),
      };

      await transaction.save();

      this.logInfo("Payment cancellation logged", {
        transactionId,
        userId: transaction.userId,
        reason: cancellationData.reason,
      });

      return transaction;
    } catch (error) {
      this.logError("Failed to log payment cancellation", error);
      throw new Error("Payment cancellation logging failed");
    }
  }

  /**
   * Get payment history for a user
   * @param {string} userId - User ID
   * @param {Object} options - Query options
   * @returns {Promise<Array>} - Payment transactions
   */
  async getUserPaymentHistory(userId, options = {}) {
    try {
      const {
        limit = 50,
        skip = 0,
        status = null,
        startDate = null,
        endDate = null,
      } = options;

      let query = { userId };

      // Add status filter
      if (status) {
        query.status = status;
      }

      // Add date range filter
      if (startDate || endDate) {
        query.createdAt = {};
        if (startDate) query.createdAt.$gte = new Date(startDate);
        if (endDate) query.createdAt.$lte = new Date(endDate);
      }

      const transactions = await PaymentTransaction.find(query)
        .sort({ createdAt: -1 })
        .limit(limit)
        .skip(skip)
        .select("-__v -updatedAt");

      this.logInfo("Payment history retrieved", {
        userId,
        count: transactions.length,
        filters: options,
      });

      return transactions;
    } catch (error) {
      this.logError("Failed to get payment history", error);
      throw new Error("Payment history retrieval failed");
    }
  }

  /**
   * Get transaction by ID
   * @param {string} transactionId - Transaction ID
   * @returns {Promise<Object>} - Transaction record
   */
  async getTransactionById(transactionId) {
    try {
      const transaction = await PaymentTransaction.findOne({ transactionId });

      if (!transaction) {
        throw new Error(`Transaction not found: ${transactionId}`);
      }

      return transaction;
    } catch (error) {
      this.logError("Failed to get transaction by ID", error);
      throw new Error("Transaction retrieval failed");
    }
  }

  /**
   * Get suspicious transactions for review
   * @param {Object} options - Query options
   * @returns {Promise<Array>} - Suspicious transactions
   */
  async getSuspiciousTransactions(options = {}) {
    try {
      const { limit = 100, skip = 0 } = options;

      const transactions = await PaymentTransaction.findSuspiciousTransactions(
        limit
      )
        .skip(skip)
        .select("-__v -updatedAt");

      this.logInfo("Suspicious transactions retrieved", {
        count: transactions.length,
        filters: options,
      });

      return transactions;
    } catch (error) {
      this.logError("Failed to get suspicious transactions", error);
      throw new Error("Suspicious transactions retrieval failed");
    }
  }

  /**
   * Get payment statistics for a user
   * @param {string} userId - User ID
   * @param {Object} options - Query options
   * @returns {Promise<Object>} - Payment statistics
   */
  async getUserPaymentStats(userId, options = {}) {
    try {
      const { startDate = null, endDate = null } = options;

      const stats = await PaymentTransaction.getTransactionStats(
        userId,
        startDate,
        endDate
      );

      // Calculate additional metrics
      const totalTransactions = stats.reduce(
        (sum, stat) => sum + stat.count,
        0
      );
      const successfulTransactions = stats.find(
        (stat) => stat._id === "succeeded"
      );
      const failedTransactions = stats.filter((stat) =>
        [
          "failed",
          "cancelled",
          "fraud_detected",
          "validation_failed",
          "rate_limited",
        ].includes(stat._id)
      );

      const successRate =
        totalTransactions > 0
          ? (
              ((successfulTransactions?.count || 0) / totalTransactions) *
              100
            ).toFixed(2)
          : 0;

      const result = {
        totalTransactions,
        successRate: `${successRate}%`,
        successfulCount: successfulTransactions?.count || 0,
        failedCount: failedTransactions.reduce(
          (sum, stat) => sum + stat.count,
          0
        ),
        totalAmount: stats.reduce(
          (sum, stat) => sum + (stat.totalAmount || 0),
          0
        ),
        averageAmount:
          stats.length > 0
            ? (
                stats.reduce((sum, stat) => sum + (stat.avgAmount || 0), 0) /
                stats.length
              ).toFixed(2)
            : 0,
        statusBreakdown: stats,
        period: {
          startDate: startDate || "all time",
          endDate: endDate || "all time",
        },
      };

      this.logInfo("Payment statistics retrieved", {
        userId,
        totalTransactions,
        successRate,
      });

      return result;
    } catch (error) {
      this.logError("Failed to get payment statistics", error);
      throw new Error("Payment statistics retrieval failed");
    }
  }

  /**
   * Update transaction with Stripe webhook data
   * @param {string} stripeSessionId - Stripe session ID
   * @param {Object} webhookData - Webhook payload
   * @returns {Promise<Object>} - Updated transaction record
   */
  async updateTransactionFromWebhook(stripeSessionId, webhookData) {
    try {
      const transaction = await PaymentTransaction.findOne({ stripeSessionId });

      if (!transaction) {
        throw new Error(
          `Transaction not found for Stripe session: ${stripeSessionId}`
        );
      }

      // Update based on webhook event type
      if (webhookData.type === "checkout.session.completed") {
        await transaction.markAsCompleted({
          paymentMethod: webhookData.data.object.payment_method_types?.[0],
          paymentStatus: webhookData.data.object.payment_status,
        });
      } else if (webhookData.type === "payment_intent.payment_failed") {
        await transaction.markAsFailed({
          code: "STRIPE_PAYMENT_FAILED",
          message: webhookData.data.object.last_payment_error?.message,
          timestamp: new Date().toISOString(),
        });
      }

      this.logInfo("Transaction updated from webhook", {
        transactionId: transaction.transactionId,
        stripeSessionId,
        webhookType: webhookData.type,
      });

      return transaction;
    } catch (error) {
      this.logError("Failed to update transaction from webhook", error);
      throw new Error("Webhook transaction update failed");
    }
  }

  /**
   * Logging helper methods
   */
  logInfo(message, data = {}) {
    if (["info", "debug"].includes(this.logLevel)) {
      console.log(`[PAYMENT_LOGGER] ${message}`, JSON.stringify(data, null, 2));
    }
  }

  logWarn(message, data = {}) {
    if (["warn", "info", "debug"].includes(this.logLevel)) {
      console.warn(
        `[PAYMENT_LOGGER] ${message}`,
        JSON.stringify(data, null, 2)
      );
    }
  }

  logError(message, error = {}) {
    console.error(`[PAYMENT_LOGGER] ${message}`, error);
  }
}

module.exports = PaymentLogger;
