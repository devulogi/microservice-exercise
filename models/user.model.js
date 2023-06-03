const { mongoose } = require('../services/mongodb');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['admin', 'user', 'visitor'],
    default: 'visitor'
  }
});

const User = mongoose.model('User', userSchema);

module.exports = { User };
