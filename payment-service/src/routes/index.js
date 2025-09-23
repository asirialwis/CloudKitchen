const express = require("express");
const {
  createCheckoutSession,
  getSessionStatus,
  getPaymentHistory,
  getPaymentStats,
  getTransactionDetails,
} = require("../controllers/paymentController");
const { paymentLimiter } = require("../middleware/rateLimiter");

const router = express.Router();

// Payment endpoints with rate limiting
router.post("/create-checkout-session", createCheckoutSession);
router.get("/session/:sessionId", paymentLimiter, getSessionStatus);

// Payment history and statistics endpoints
router.get("/history", paymentLimiter, getPaymentHistory);
router.get("/stats", paymentLimiter, getPaymentStats);
router.get(
  "/transaction/:transactionId",
  paymentLimiter,
  getTransactionDetails
);

// Health check endpoint
router.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    service: "payment-service",
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;
