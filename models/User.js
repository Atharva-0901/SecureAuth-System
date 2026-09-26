// ============================================
// models/User.js — THE USER DATABASE SCHEMA
// ============================================


const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({

  // ─── Basic Info ──────────────────────────────
  name: {
    type: String,
    required: true,
    trim: true                     
  },
  email: {
    type: String,
    required: true,
    unique: true,                   
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 8                    
  },

  // ─── Email Verification ──────────────────────
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailOTP: String,                 
  emailOTPExpiry: Date,             

  // ─── Two-Factor Authentication (2FA) ─────────
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: String,         

  // ─── Password Reset ──────────────────────────
  passwordResetToken: String,       
  passwordResetExpiry: Date,        

  // ─── Refresh Token (for staying logged in) ───
  refreshToken: String,

  // ─── Login Attempt Tracking ──────────────────
  // Used to lock the account after too many failed attempts
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,                  

}, {
  timestamps: true                 
});

// ─── MIDDLEWARE: Hash Password Before Saving ────

userSchema.pre('save', async function(next) {
)
  if (!this.isModified('password')) return next();

  // bcrypt.hash(plainText, saltRounds)
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// ─── METHOD: Compare Passwords ───────────────

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// ─── METHOD: Check if Account is Locked ──────
userSchema.methods.isLocked = function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

// ─── VIRTUAL: Remove password from JSON responses ─

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
