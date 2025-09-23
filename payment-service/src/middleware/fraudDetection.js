/**
 * Fraud Detection Middleware for Payment Service
 * Detects suspicious patterns and blocks potentially fraudulent transactions
 */

class FraudDetection {
  constructor() {
    // Risk thresholds
    this.HIGH_RISK_THRESHOLD = 100;
    this.MEDIUM_RISK_THRESHOLD = 50;
    this.LOW_RISK_THRESHOLD = 20;

    // Suspicious patterns
    this.SUSPICIOUS_PATTERNS = {
      // Price manipulation patterns
      NEGATIVE_PRICES: "negative_prices",
      EXTREME_PRICES: "extreme_prices",
      PRICE_MANIPULATION: "price_manipulation",

      // Quantity manipulation patterns
      EXTREME_QUANTITIES: "extreme_quantities",
      QUANTITY_OVERFLOW: "quantity_overflow",

      // Behavioral patterns
      RAPID_SUCCESSIVE_PAYMENTS: "rapid_successive_payments",
      UNUSUAL_PAYMENT_TIMES: "unusual_payment_times",
      UNUSUAL_PAYMENT_AMOUNTS: "unusual_payment_amounts",

      // Technical patterns
      SUSPICIOUS_USER_AGENT: "suspicious_user_agent",
      SUSPICIOUS_IP: "suspicious_ip",
      MISSING_HEADERS: "missing_headers",
    };
  }

  /**
   * Main fraud detection method
   * @param {Object} req - Express request object
   * @param {Object} paymentData - Validated payment data
   * @param {Object} userHistory - User's payment history
   * @returns {Object} - Fraud detection result
   */
  detectFraud(req, paymentData, userHistory = {}) {
    const fraudIndicators = [];
    let riskScore = 0;

    // Check for price manipulation
    const priceAnalysis = this.analyzePricePatterns(paymentData.items);
    if (priceAnalysis.isSuspicious) {
      fraudIndicators.push(...priceAnalysis.indicators);
      riskScore += priceAnalysis.riskScore;
    }

    // Check for quantity manipulation
    const quantityAnalysis = this.analyzeQuantityPatterns(paymentData.items);
    if (quantityAnalysis.isSuspicious) {
      fraudIndicators.push(...quantityAnalysis.indicators);
      riskScore += quantityAnalysis.riskScore;
    }

    // Check for behavioral patterns
    const behavioralAnalysis = this.analyzeBehavioralPatterns(req, userHistory);
    if (behavioralAnalysis.isSuspicious) {
      fraudIndicators.push(...behavioralAnalysis.indicators);
      riskScore += behavioralAnalysis.riskScore;
    }

    // Check for technical patterns
    const technicalAnalysis = this.analyzeTechnicalPatterns(req);
    if (technicalAnalysis.isSuspicious) {
      fraudIndicators.push(...technicalAnalysis.indicators);
      riskScore += technicalAnalysis.riskScore;
    }

    // Check for total amount anomalies
    const amountAnalysis = this.analyzeAmountPatterns(
      paymentData.totalAmount,
      userHistory
    );
    if (amountAnalysis.isSuspicious) {
      fraudIndicators.push(...amountAnalysis.indicators);
      riskScore += amountAnalysis.riskScore;
    }

    return {
      isFraudulent: riskScore >= this.HIGH_RISK_THRESHOLD,
      isSuspicious: riskScore >= this.MEDIUM_RISK_THRESHOLD,
      riskScore: riskScore,
      fraudIndicators: fraudIndicators,
      recommendation: this.getRecommendation(riskScore),
      requiresReview: riskScore >= this.MEDIUM_RISK_THRESHOLD,
    };
  }

  /**
   * Analyze price patterns for fraud
   */
  analyzePricePatterns(items) {
    const indicators = [];
    let riskScore = 0;

    // Check for negative prices
    const negativePrices = items.filter((item) => item.price < 0);
    if (negativePrices.length > 0) {
      indicators.push({
        type: this.SUSPICIOUS_PATTERNS.NEGATIVE_PRICES,
        severity: "HIGH",
        message: "Negative prices detected",
        count: negativePrices.length,
      });
      riskScore += 100;
    }

    // Check for extreme prices
    const extremePrices = items.filter((item) => item.price > 5000);
    if (extremePrices.length > 0) {
      indicators.push({
        type: this.SUSPICIOUS_PATTERNS.EXTREME_PRICES,
        severity: "MEDIUM",
        message: "Extremely high prices detected",
        count: extremePrices.length,
      });
      riskScore += 50;
    }

    // Check for price manipulation patterns
    const prices = items.map((item) => item.price);
    const avgPrice =
      prices.reduce((sum, price) => sum + price, 0) / prices.length;
    const priceVariance =
      prices.reduce((sum, price) => sum + Math.pow(price - avgPrice, 2), 0) /
      prices.length;

    if (priceVariance > 1000000) {
      // High variance
      indicators.push({
        type: this.SUSPICIOUS_PATTERNS.PRICE_MANIPULATION,
        severity: "MEDIUM",
        message: "Unusual price variance detected",
        variance: priceVariance,
      });
      riskScore += 30;
    }

    return {
      isSuspicious: indicators.length > 0,
      indicators: indicators,
      riskScore: riskScore,
    };
  }

  /**
   * Analyze quantity patterns for fraud
   */
  analyzeQuantityPatterns(items) {
    const indicators = [];
    let riskScore = 0;

    // Check for extreme quantities
    const extremeQuantities = items.filter((item) => item.quantity > 50);
    if (extremeQuantities.length > 0) {
      indicators.push({
        type: this.SUSPICIOUS_PATTERNS.EXTREME_QUANTITIES,
        severity: "MEDIUM",
        message: "Extremely high quantities detected",
        count: extremeQuantities.length,
      });
      riskScore += 40;
    }

    // Check for quantity overflow
    const totalQuantity = items.reduce((sum, item) => sum + item.quantity, 0);
    if (totalQuantity > 1000) {
      indicators.push({
        type: this.SUSPICIOUS_PATTERNS.QUANTITY_OVERFLOW,
        severity: "HIGH",
        message: "Total quantity exceeds normal limits",
        totalQuantity: totalQuantity,
      });
      riskScore += 60;
    }

    return {
      isSuspicious: indicators.length > 0,
      indicators: indicators,
      riskScore: riskScore,
    };
  }

  /**
   * Analyze behavioral patterns
   */
  analyzeBehavioralPatterns(req, userHistory) {
    const indicators = [];
    let riskScore = 0;

    // Check for rapid successive payments
    if (userHistory.recentPayments > 10) {
      indicators.push({
        type: this.SUSPICIOUS_PATTERNS.RAPID_SUCCESSIVE_PAYMENTS,
        severity: "HIGH",
        message: "Rapid successive payments detected",
        count: userHistory.recentPayments,
      });
      riskScore += 50;
    }

    // Check for unusual payment times (if available)
    const currentHour = new Date().getHours();
    if (currentHour < 6 || currentHour > 23) {
      indicators.push({
        type: this.SUSPICIOUS_PATTERNS.UNUSUAL_PAYMENT_TIMES,
        severity: "LOW",
        message: "Payment made during unusual hours",
        hour: currentHour,
      });
      riskScore += 10;
    }

    return {
      isSuspicious: indicators.length > 0,
      indicators: indicators,
      riskScore: riskScore,
    };
  }

  /**
   * Analyze technical patterns
   */
  analyzeTechnicalPatterns(req) {
    const indicators = [];
    let riskScore = 0;

    // Check for suspicious user agent
    const userAgent = req.headers["user-agent"] || "";
    const suspiciousPatterns = [
      /curl/i,
      /wget/i,
      /python/i,
      /bot/i,
      /spider/i,
      /scraper/i,
      /automated/i,
    ];

    if (suspiciousPatterns.some((pattern) => pattern.test(userAgent))) {
      indicators.push({
        type: this.SUSPICIOUS_PATTERNS.SUSPICIOUS_USER_AGENT,
        severity: "MEDIUM",
        message: "Suspicious user agent detected",
        userAgent: userAgent,
      });
      riskScore += 30;
    }

    // Check for missing important headers
    const requiredHeaders = ["user-agent", "accept"];
    const missingHeaders = requiredHeaders.filter(
      (header) => !req.headers[header]
    );

    if (missingHeaders.length > 0) {
      indicators.push({
        type: this.SUSPICIOUS_PATTERNS.MISSING_HEADERS,
        severity: "LOW",
        message: "Missing important headers",
        missingHeaders: missingHeaders,
      });
      riskScore += 15;
    }

    return {
      isSuspicious: indicators.length > 0,
      indicators: indicators,
      riskScore: riskScore,
    };
  }

  /**
   * Analyze amount patterns
   */
  analyzeAmountPatterns(totalAmount, userHistory) {
    const indicators = [];
    let riskScore = 0;

    // Check for unusual payment amounts
    if (userHistory.avgOrderValue) {
      const amountRatio = totalAmount / userHistory.avgOrderValue;

      if (amountRatio > 20) {
        indicators.push({
          type: this.SUSPICIOUS_PATTERNS.UNUSUAL_PAYMENT_AMOUNTS,
          severity: "HIGH",
          message: "Payment amount significantly higher than average",
          ratio: amountRatio,
          totalAmount: totalAmount,
          avgOrderValue: userHistory.avgOrderValue,
        });
        riskScore += 70;
      } else if (amountRatio > 10) {
        indicators.push({
          type: this.SUSPICIOUS_PATTERNS.UNUSUAL_PAYMENT_AMOUNTS,
          severity: "MEDIUM",
          message: "Payment amount higher than average",
          ratio: amountRatio,
          totalAmount: totalAmount,
          avgOrderValue: userHistory.avgOrderValue,
        });
        riskScore += 40;
      }
    }

    return {
      isSuspicious: indicators.length > 0,
      indicators: indicators,
      riskScore: riskScore,
    };
  }

  /**
   * Get recommendation based on risk score
   */
  getRecommendation(riskScore) {
    if (riskScore >= this.HIGH_RISK_THRESHOLD) {
      return "BLOCK";
    } else if (riskScore >= this.MEDIUM_RISK_THRESHOLD) {
      return "REVIEW";
    } else if (riskScore >= this.LOW_RISK_THRESHOLD) {
      return "MONITOR";
    } else {
      return "ALLOW";
    }
  }

  /**
   * Log fraud detection results
   */
  logFraudDetection(result, req, paymentData) {
    const logData = {
      timestamp: new Date().toISOString(),
      userId: req.headers["x-user-id"],
      ip: req.ip,
      userAgent: req.headers["user-agent"],
      riskScore: result.riskScore,
      recommendation: result.recommendation,
      fraudIndicators: result.fraudIndicators,
      totalAmount: paymentData.totalAmount,
      itemCount: paymentData.itemCount,
    };

    if (result.isFraudulent) {
      console.error("🚨 FRAUD DETECTED:", JSON.stringify(logData, null, 2));
    } else if (result.isSuspicious) {
      console.warn("⚠️ SUSPICIOUS ACTIVITY:", JSON.stringify(logData, null, 2));
    } else {
      console.info("✅ Payment validated:", JSON.stringify(logData, null, 2));
    }
  }
}

module.exports = FraudDetection;
