const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const router = require('express').Router();

const { redisClient } = require('../services/redis');
const { ensureAuthenticated, CustomError } = require('../helpers');
const { User } = require('../models/user.model');

router.post('/register', async (req, res, next) => {
  const isEmailTaken = await User.exists({ email: req.body.email });
  if (isEmailTaken) {
    return res.status(400).send({
      description: 'Email already taken',
      hint: 'Please use a different email address',
      metadata: {
        timestamp: new Date().toISOString(),
        request: {
          method: req.method,
          url: req.originalUrl,
          payload: req.body
        }
      }
    });
  }
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const user = new User({
    email: req.body.email,
    password: hashedPassword,
    role: req.body.role
  });
  await user.save();
  res.status(201).send();
});

router.post('/login', async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });

  if (user && await bcrypt.compare(req.body.password, user.password)) {
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '5m' });
    const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_SECRET);
    
    // Store refresh token in Redis
    redisClient.set(refreshToken, user._id.toString(), 'EX', 60 * 60 * 1); // 1 hour expiration (seconds, minutes, hours)

    // Set refresh token as a cookie in the response header
    res.cookie('refreshToken', refreshToken, { httpOnly: true });

    res.send({ token });
  } else {
    const error = new CustomError({
      message: 'Invalid email or password',
      hint: 'Please try again',
      statusCode: 401
    });

    return next(error);
  }
});

router.post('/refresh', async (req, res) => {
  // Check if refresh token exists in the cookie header
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    const error = new CustomError({
      message: 'No refresh token found in the cookie header',
      hint: 'Please login again',
      statusCode: 401
    });

    return next(error);
  }

  // Check if refresh token exists in Redis
  const rt = await redisClient.get(refreshToken);

  if (!rt || rt === 'revoked') {
    const error = new CustomError({
      description: rt === 'revoked' ? 'Token has been revoked' : 'Refresh token not found in the Redis database',
      hint: 'Please login again',
      statusCode: 403
    });
    
    return next(error);
  }

  jwt.verify(refreshToken, process.env.REFRESH_SECRET, async (err, user) => {

    if (err) {
      return res.status(403).send({
        description: 'Invalid refresh token',
        hint: 'Please login again',
        metadata: {
          timestamp: new Date().toISOString(),
          request: {
            method: req.method,
            url: req.originalUrl,
            payload: req.body
          }
        }
      });
    }

    await redisClient.del(refreshToken);

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '30s' });
    res.send({ token });
  });
});

router.post('/revoke', async (req, res) => {
  const token = req.headers['authorization'].split(' ')[1] 
    ? req.headers['authorization'].split(' ')[1] 
    : null;

  if (!token || token === 'null') {
    return res.status(401).send({
      description: 'No token found in the authorization header',
      hint: 'Please login again',
      metadata: {
        timestamp: new Date().toISOString(),
        request: {
          method: req.method,
          url: req.originalUrl,
          payload: req.body
        }
      }
    });
  }

  redisClient.set(token, 'revoked');

  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).send({
      description: 'No refresh token found in the cookie header',
      hint: 'Please login again',
      metadata: {
        timestamp: new Date().toISOString(),
        request: {
          method: req.method,
          url: req.originalUrl,
          payload: req.body
        }
      }
    });
  }

  redisClient.set(refreshToken, 'revoked');

  res.status(200).send({
    description: 'Token has been revoked',
    metadata: {
      timestamp: new Date().toISOString(),
      request: {
        method: req.method,
        url: req.originalUrl,
        payload: req.body
      }
    }
  });
});

router.post('/logout', async (req, res) => {
  const refreshToken = req.cookies.refreshToken; // Retrieve refresh token from the cookie

  if (refreshToken) {
    redisClient.del(refreshToken);
  }

  // Clear refresh token cookie
  res.clearCookie('refreshToken');

  res.status(204).send();
});

router.post('/flush-tokens', async (req, res) => {
  redisClient.flushDb();
  res.status(204).send();
});

router.get('/protected', ensureAuthenticated, (req, res) => {
  res.send({
    message: 'Welcome to the protected route',
    description: 'This is a protected route. You can only access this if you are logged in.',
    data: req.user,
    metadata: {
      timestamp: new Date().toISOString(),
      request: {
        method: req.method,
        url: req.originalUrl
      }
    }
  });
});

module.exports = router;
