const redis = require('redis');
const dotenv = require('dotenv');
dotenv.config(); // Load environment variables from .env file

const redisClient = redis.createClient({
  url: `redis://${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`,
});
redisClient.connect()
redisClient.on('error', err => {
    console.error('Redis error:', err);
  })
  .on('connect', () => {
    console.log('Connected to Redis');
  })
  .on('ready', () => {
    console.log('Redis is ready');
  });

module.exports = { redisClient };
