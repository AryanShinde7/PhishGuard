/**
 * config/db.js — MongoDB Connection Manager
 *
 * Connects to MongoDB Atlas using Mongoose.
 * Called once at server startup. Handles reconnection automatically.
 *
 * Usage: require('./config/db')() at the top of server.js
 */

const mongoose = require('mongoose');

const connectDB = async () => {
  const uri = process.env.MONGO_URI;

  if (!uri) {
    console.error('[PhishGuard DB] ❌  MONGO_URI is not set in .env — MongoDB not connected.');
    console.error('[PhishGuard DB]    The API will run but data will NOT be persisted.');
    return;
  }

  try {
    const conn = await mongoose.connect(uri, {
      // Mongoose 8+ doesn't need deprecated options
    });

    console.log(`[PhishGuard DB] ✅  MongoDB connected: ${conn.connection.host}`);

    // Connection event listeners
    mongoose.connection.on('disconnected', () => {
      console.warn('[PhishGuard DB] ⚠️  MongoDB disconnected. Attempting to reconnect...');
    });

    mongoose.connection.on('reconnected', () => {
      console.log('[PhishGuard DB] ✅  MongoDB reconnected.');
    });

    mongoose.connection.on('error', (err) => {
      console.error('[PhishGuard DB] ❌  MongoDB error:', err.message);
    });

  } catch (err) {
    console.error('[PhishGuard DB] ❌  Connection failed:', err.message);
    console.error('[PhishGuard DB]    Check your MONGO_URI in .env file.');
    // Don't crash the process — API still works without DB (returns empty data)
  }
};

module.exports = connectDB;
