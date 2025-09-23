const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const { connectRabbitMQ } = require("./utils/rabbitmq");
const Redis = require("ioredis");
const { RedisStore } = require("rate-limit-redis");
const rateLimit = require("express-rate-limit");

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors({ origin: "http://localhost:5173" }));

// Create Redis client with ioredis
const redisClient = new Redis("redis://redis:6379");

redisClient.on("connect", () => {
  console.log("✅ Redis Connected");
});

redisClient.on("error", (err) => {
  console.error("❌ Redis Error:", err);
});

// Use an async function to handle startup
const startServer = async () => {
  try {
    // Rate limiter using Redis
    const loginLimiter = rateLimit({
      store: new RedisStore({
        sendCommand: (...args) => redisClient.call(...args),
      }),
      windowMs: 60 * 60 * 1000,
      max: 5,
      message: "Too many login attempts, please try again after an hour.",
    });

    // Connect to RabbitMQ
    connectRabbitMQ();

    // Connect to MongoDB
    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ MongoDB Connected");

    // Pass limiter to routes
    app.use("/user", require("./routes/authRoutes")(loginLimiter));

    const PORT = process.env.PORT || 5001;
    app.listen(PORT, () =>
      console.log(`🚀 Auth Service running on port ${PORT}`)
    );

  } catch (err) {
    console.error("❌ A startup error occurred:", err);
    process.exit(1);
  }
};

startServer();
