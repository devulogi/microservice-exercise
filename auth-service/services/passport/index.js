const passport = require('passport');
const JWTStrategy = require('./strategies/jwtStrategy');

JWTStrategy(passport);

module.exports = { passport };
