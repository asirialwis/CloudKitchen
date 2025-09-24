const { OAuth2Client } = require("google-auth-library");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
require("dotenv").config();

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const generateAccessToken = (user) => {
  return jwt.sign(
    { id: user._id, role: user.role, email: user.email },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRE_TIME }
  );
};

const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user._id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRE_TIME }
  );
};

// POST /user/oauth/google
// Body: { credential: string }
module.exports = async function googleSignin(req, res) {
  try {
    const { credential } = req.body || {};
    if (!credential) {
      return res.status(400).json({ message: "Missing Google credential" });
    }

    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    const {
      sub: providerId,
      email,
      name,
      picture,
      email_verified: emailVerified,
    } = payload || {};

    if (!email) {
      return res.status(400).json({ message: "Google account has no email" });
    }

    // Find or create user by email
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({
        name: name || email,
        email,
        password: undefined, // no password for social login
        role: "customer", // default role
        provider: "google",
        providerId,
        picture,
        emailVerified: !!emailVerified,
        refreshTokens: [],
      });
    } else {
      // Update social metadata if not set
      if (!user.provider) user.provider = "google";
      if (!user.providerId) user.providerId = providerId;
      if (picture && !user.picture) user.picture = picture;
      if (typeof user.emailVerified === "undefined") user.emailVerified = !!emailVerified;
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Ensure refresh token uniqueness in array and rotate
    user.refreshTokens = (user.refreshTokens || []).filter((entry) => {
      if (typeof entry === "string") return entry !== refreshToken;
      return entry?.token !== refreshToken;
    });
    user.refreshTokens.push({ token: refreshToken, lastUsedAt: new Date() });
    await user.save();

    const isProd = process.env.NODE_ENV === "production";
    const sameSite = isProd ? "lax" : "lax";
    const domain = undefined;

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: isProd,
      sameSite,
      domain,
      path: "/",
      maxAge: 1000 * 60 * 15,
    });
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite,
      domain,
      path: "/",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });

  return res.status(200).json({ message: "Signed in with Google" });
  } catch (err) {
    return res.status(401).json({ message: "Google sign-in failed", error: err.message });
  }
}
