const express = require("express");
const router = express.Router();
const userSignup = require("../controllers/signup");
const userSignin = require("../controllers/signin");
const userAuth = require("../middleware/authMiddleware");
const refreshToken = require("../middleware/refreshToken");
const userSignout = require("../controllers/signout");
const verify = require("../controllers/verify");
const googleSignin = require("../controllers/googleSignin");

router.post("/signup", userSignup);
router.post("/signin/restaurant-admin",userSignin(["restaurant-admin"]));
router.post("/signin/delivery",userSignin(["delivery"]));
router.post("/signin/customer",userSignin(["customer"]));
router.post("/refresh-token",refreshToken)
router.post("/signout",userSignout)
router.get("/verify-token",verify)
router.post("/oauth/google", googleSignin)



module.exports = router;
