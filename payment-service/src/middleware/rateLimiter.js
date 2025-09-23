const rateLimit = require("express-rate-limit");

/**
 * Rate limiting configurations for payment service
 */

// General payment rate limiter
const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 payment attempts per IP per window
  message: {
    error: "Too many payment attempts, please try again later",
    retryAfter: "15 minutes",
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful requests
  skipFailedRequests: false, // Count failed requests
  keyGenerator: (req) => {
    // Use user ID if available, otherwise IP
    return req.headers["x-user-id"] || req.ip;
  },
  onLimitReached: (req, res, options) => {
    console.warn(
      `Rate limit reached for payment endpoint: ${req.ip} - ${req.headers["x-user-id"]}`
    );
  },
});

// Strict rate limiter for checkout session creation
const checkoutLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // 5 checkout sessions per IP per window
  message: {
    error: "Too many checkout attempts, please try again later",
    retryAfter: "5 minutes",
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    return req.headers["x-user-id"] || req.ip;
  },
  onLimitReached: (req, res, options) => {
    console.warn(
      `Checkout rate limit reached: ${req.ip} - ${req.headers["x-user-id"]}`
    );
  },
});

// Very strict limiter for suspicious activity
const suspiciousActivityLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 2, // 2 attempts per minute
  message: {
    error: "Suspicious activity detected, please try again later",
    retryAfter: "1 minute",
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    return req.headers["x-user-id"] || req.ip;
  },
  onLimitReached: (req, res, options) => {
    console.error(
      `Suspicious activity rate limit reached: ${req.ip} - ${req.headers["x-user-id"]}`
    );
  },
});

module.exports = {
  paymentLimiter,
  checkoutLimiter,
  suspiciousActivityLimiter,
};
