const User = require("../models/User");

const logout = async (req, res) => {
    try {
        const refreshToken = req.cookies?.refreshToken || req.headers.authorization?.split(" ")[1];

        if (!refreshToken) {
            return res.status(400).json({ message: "Refresh token required." });
        }

        // Find user with the given refresh token
        const user = await User.findOne({ "refreshTokens.token": refreshToken });
        if (!user) {
            return res.status(400).json({ message: "Invalid refresh token." });
        }

        // Remove the refresh token from the array
        user.refreshTokens = user.refreshTokens.filter((s) => (s.token || s) !== refreshToken);

        // Save the updated user document
        await user.save();

        // Clear cookies
        const isProd = process.env.NODE_ENV === "production";
        const sameSite = isProd ? "lax" : "lax";
        res.clearCookie("accessToken", { httpOnly: true, secure: isProd, sameSite, path: "/" });
        res.clearCookie("refreshToken", { httpOnly: true, secure: isProd, sameSite, path: "/" });

        return res.status(200).json({ message: "Signout successful. Token removed." });
    } catch (error) {
        return res.status(500).json({ message: "Logout failed.", error: error.message });
    }
};

module.exports = logout;
