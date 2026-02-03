// ============================================
// models/User.js — THE USER DATABASE SCHEMA
// ============================================
// This defines what a "User" looks like in MongoDB.
// Schema = the blueprint. Like a form with specific fields.
// Mongoose enforces this structure automatically.

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({

  // ─── Basic Info ──────────────────────────────
  name: {
    type: String,
    required: true,
    trim: true                      // Removes extra spaces
  },
  email: {
    type: String,
    required: true,
    unique: true,                   // No two users can share an email
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email'] // Basic email regex
  },
  password: {
    type: String,
    required: true,
    minlength: 8                    // Minimum 8 characters
  },

  // ─── Email Verification ──────────────────────
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailOTP: String,                 // The 6-digit code we send via email
  emailOTPExpiry: Date,             // When the OTP expires (e.g., 10 min)

  // ─── Two-Factor Authentication (2FA) ─────────
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: String,         // The secret used to generate TOTP codes

  // ─── Password Reset ──────────────────────────
  passwordResetToken: String,       // A unique token sent via email
  passwordResetExpiry: Date,        // When the reset link expires

  // ─── Refresh Token (for staying logged in) ───
  refreshToken: String,

  // ─── Login Attempt Tracking ──────────────────
  // Used to lock the account after too many failed attempts
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,                  // Timestamp when account unlocks

}, {
  timestamps: true                  // Adds createdAt and updatedAt automatically
});

// ─── MIDDLEWARE: Hash Password Before Saving ────
// "pre('save')" means: run this function BEFORE saving to DB
// We NEVER store plain text passwords!
userSchema.pre('save', async function(next) {
  // Only hash if password was changed (or is new)
  if (!this.isModified('password')) return next();

  // bcrypt.hash(plainText, saltRounds)
  // Salt rounds = 12 means the hashing runs 2^12 = 4096 iterations
  // More iterations = harder to crack, but slower
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// ─── METHOD: Compare Passwords ───────────────
// We use this when the user tries to log in
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// ─── METHOD: Check if Account is Locked ──────
userSchema.methods.isLocked = function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

// ─── VIRTUAL: Remove password from JSON responses ─
// When we send user data to the frontend, this REMOVES the password field
// So it never accidentally leaks
userSchema.methods.toJSON = function() {
  const user = this.toObject();
  delete user.password;
  delete user.emailOTP;
  delete user.emailOTPExpiry;
  delete user.passwordResetToken;
  delete user.passwordResetExpiry;
  delete user.twoFactorSecret;
  delete user.refreshToken;
  delete user.__v;
  return user;
};

module.exports = mongoose.model('User', userSchema);
