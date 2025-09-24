const jwt = require("jsonwebtoken");
require("dotenv").config();
const User = require("../models/User");

// Function to generate access token
const generateAccessToken = (user) => {
    return jwt.sign(
        { id: user.id, role: user.role,email: user.email },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: process.env.ACCESS_TOKEN_EXPIRE_TIME }
    );
};

const refreshTokenHandler = async (req, res) => {
    try {
        // Read refresh token from HttpOnly cookie
        const refreshToken = req.cookies?.refreshToken;
        if (!refreshToken) {
            return res.status(401).json({ message: "Access Denied. No refresh token." });
        }

        // Find user with this refresh token
        let user = await User.findOne({ "refreshTokens.token": refreshToken });
        if (!user) {
            return res.status(403).json({ message: "Invalid refresh token." });
        }

        jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, decoded) => {
            if (err) return res.status(403).json({ message: "Expired or invalid refresh token." });

            // Optional: Inactivity timeout (e.g., 30 minutes)
            const now = Date.now();
            const session = (user.refreshTokens || []).find((s) => (s.token || s) === refreshToken);
            if (session && session.lastUsedAt) {
                const idleMs = now - new Date(session.lastUsedAt).getTime();
                const MAX_IDLE_MS = 1000 * 60 * 30; // 30 minutes
                if (idleMs > MAX_IDLE_MS) {
                    // remove stale session
                    user.refreshTokens = user.refreshTokens.filter((s) => (s.token || s) !== refreshToken);
                    await user.save();
                    return res.status(440).json({ message: "Session expired due to inactivity." });
                }
            }

            // Rotate refresh token and issue new access token
            const newAccessToken = generateAccessToken(user);
            const newRefreshToken = jwt.sign(
                { id: user._id },
                process.env.REFRESH_TOKEN_SECRET,
                { expiresIn: process.env.REFRESH_TOKEN_EXPIRE_TIME }
            );

            // Replace old refresh token with new one
            user.refreshTokens = (user.refreshTokens || []).filter((s) => (s.token || s) !== refreshToken);
            user.refreshTokens.push({ token: newRefreshToken, lastUsedAt: new Date() });
            await user.save();

            const isProd = process.env.NODE_ENV === "production";
            const sameSite = isProd ? "lax" : "lax";

            res.cookie("accessToken", newAccessToken, {
                httpOnly: true,
                secure: isProd,
                sameSite,
                path: "/",
                maxAge: 1000 * 60 * 15,
            });
            res.cookie("refreshToken", newRefreshToken, {
                httpOnly: true,
                secure: isProd,
                sameSite,
                path: "/",
                maxAge: 1000 * 60 * 60 * 24 * 7,
            });

            return res.status(200).json({ message: "Token refreshed" });
        });
    } catch (error) {
        return res.status(500).json({ message: "Token refresh failed.", error: error.message });
    }
};

module.exports = refreshTokenHandler;
