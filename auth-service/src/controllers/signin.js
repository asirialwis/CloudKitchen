const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();
const User = require("../models/User");


const generateAccessToken = (user) => {
    return jwt.sign(
        { id: user._id, role: user.role,email: user.email },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: process.env.ACCESS_TOKEN_EXPIRE_TIME } 
    );
};

// Function to generate refresh token
const generateRefreshToken = (user) => {
    return jwt.sign(
        { id: user._id },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: process.env.REFRESH_TOKEN_EXPIRE_TIME } 
    );
};

const userSignin = (allowedRoles) => async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if the user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        // Verify password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(403).json({ message: "Incorrect password." });
        }

        // Check if the user's role is allowed
        // if (!allowedRoles.includes(user.role)) {
        //     return res.status(403).json({ message: "Access Denied: You do not have permission." });
        // }

        // Generate access and refresh tokens
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        // Rotate refresh tokens: remove any identical tokens then add new
        // Support both legacy string array and new object array
        user.refreshTokens = (user.refreshTokens || []).filter((entry) => {
            if (typeof entry === "string") return entry !== refreshToken;
            return entry?.token !== refreshToken;
        });
        user.refreshTokens.push({ token: refreshToken, lastUsedAt: new Date() });
        await user.save();

        const isProd = process.env.NODE_ENV === "production";
        const sameSite = isProd ? "lax" : "lax";
        const domain = undefined; // default to host

        // Set HttpOnly cookies
        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: isProd,
            sameSite,
            domain,
            path: "/",
            maxAge: 1000 * 60 * 15, // 15 minutes
        });
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: isProd,
            sameSite,
            domain,
            path: "/",
            maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
        });

        return res.status(200).json({ message: "Signed in" });
    } catch (error) {
        return res.status(500).json({ message: "Login failed.", error: error.message });
    }
};

module.exports = userSignin;
