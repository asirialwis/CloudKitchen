const rateLimit = require("express-rate-limit");
const RedisStore = require("rate-limit-redis");
const  createClient  = require("redis");

const redisClient = createClient({
  url: 'redis://redis:6379'
});
redisClient.connect().catch(console.error);

const loginLimiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Allow only 5 login attempts per hour
  message: "Too many login attempts from this IP, please try again after an hour."
});

// Export the limiter so other files can use it
module.exports = loginLimiter;