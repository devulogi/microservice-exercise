const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const dotenv = require('dotenv');
dotenv.config(); // Load environment variables from .env file

const { User } = require("../../../models/user.model");

const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET
};

module.exports = function(passport) {
  passport.use(new JwtStrategy(opts, async (jwt_payload, done) => {
    const user = await User.findById(jwt_payload.id);
    if (!user) return done(null, false);

    return done(null, { id: user._id, email: user.email, role: user.role });
  }));
}
