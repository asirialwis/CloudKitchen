// authRoutes.js
module.exports = (loginLimiter) => {
  const express = require("express");
  const router = express.Router();
  const userSignup = require("../controllers/signup");
  const userSignin = require("../controllers/signin");
  const userAuth = require("../middleware/authMiddleware");
  const refreshToken = require("../middleware/refreshToken");
  const userSignout = require("../controllers/signout");
  const verify = require("../controllers/verify");

  router.post("/signup", userSignup);
  router.post("/signin/restaurant-admin", loginLimiter, userSignin(["restaurant-admin"]));
  router.post("/signin/delivery", loginLimiter, userSignin(["delivery"]));
  router.post("/signin/customer", loginLimiter, userSignin(["customer"]));
  router.post("/refresh-token", refreshToken);
  router.post("/signout", userSignout);
  router.get("/verify-token", verify);

  return router;
};
