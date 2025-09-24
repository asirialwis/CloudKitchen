const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ["customer", "restaurant-admin", "delivery"], default: "customer" },
  refreshTokens: {
    type: [
      new mongoose.Schema(
        {
          token: { type: String, required: true },
          lastUsedAt: { type: Date, default: Date.now },
        },
        { _id: false }
      ),
    ],
    default: [],
  },
  location: {
    lat: Number,
    lng: Number,
  },
  // Social login metadata (optional)
  provider: { type: String }, // e.g., 'google'
  providerId: { type: String }, // e.g., Google sub
  picture: { type: String },
  emailVerified: { type: Boolean },
});

module.exports = mongoose.model("User", UserSchema);
