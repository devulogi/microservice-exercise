const mongoose = require('mongoose');

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.on('error', (err) => {
  console.error('MongoDB error:', err);
});
db.once('open', () => {
  console.log('Connected to MongoDB');
});

module.exports = { db, mongoose };
