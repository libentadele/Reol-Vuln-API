const mongoose = require('mongoose');

async function connect(uri) {
  const u = uri || process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/vulndb';
  try {
    await mongoose.connect(u);
    console.log('Connected to MongoDB at', u);
  } catch (error) {
    console.error('MongoDB connection error:', error.message);
    throw error;
  }
}

module.exports = { connect, mongoose };
