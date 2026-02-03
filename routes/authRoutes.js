// ============================================
// routes/authRoutes.js — ALL AUTHENTICATION ROUTES
// ============================================
// This file defines WHAT URLs exist and WHAT happens when hit.
// Route = URL path + HTTP method + handler function
//
// POST /api/auth/register     → Create account
// POST /api/auth/login        → Log in
// POST /api/auth/verify-otp   → Verify email OTP
// POST /api/auth/resend-otp   → Resend OTP
// POST /api/auth/refresh      → Get a new access token
// POST /api/auth/logout       → Invalidate refresh token
// POST /api/auth/forgot-password  → Send reset email
// POST /api/auth/reset-password   → Actually reset the password
// POST /api/auth/2fa/setup    → Set up 2FA (returns QR code)
// POST /api/auth/2fa/enable   → Enable 2FA (verify the code)
// POST /api/auth/2fa/verify   → Verify 2FA during login

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy'); // For TOTP (Time-based One-Time Password)
const QRCode = require('qrcode');       // Generates QR code images
const User = require('../models/User');
const { protect } = require('../middleware/auth');
const {
  generateAccessToken,
  generateRefreshToken,
  generateOTP,
  sendEmail,
  otpEmailTemplate,
  resetPasswordEmailTemplate
} = require('../utils/helpers');

// ─────────────────────────────────────────────
// REGISTER
// ─────────────────────────────────────────────
// What happens: User fills form → we create account → send OTP email
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // ── Validation ──
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    // Password strength check
    // Must have: 8+ chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        success: false,
        message: 'Password must be 8+ characters with uppercase, lowercase, number, and special character'
      });
    }

    // ── Check if email already exists ──
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    // ── Create the user ──
    const user = new User({ name, email, password });

    // ── Generate OTP and set expiry (10 minutes from now) ──
    const otp = generateOTP();
    user.emailOTP = otp;
    user.emailOTPExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 min

    await user.save(); // This triggers the pre-save hook that hashes the password!

    // ── Send OTP via email ──
    await sendEmail({
      to: email,
      subject: 'SecureAuth — Verify Your Email',
      html: otpEmailTemplate(otp)
    });

    res.status(201).json({
      success: true,
      message: 'Account created! Check your email for the verification code.',
      data: { email }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// VERIFY OTP (Email Verification)
// ─────────────────────────────────────────────
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'User not found' });
    }

    // Already verified?
    if (user.isEmailVerified) {
      return res.status(400).json({ success: false, message: 'Email already verified' });
    }

    // Check if OTP expired
    if (user.emailOTPExpiry < new Date()) {
      return res.status(400).json({ success: false, message: 'OTP has expired. Request a new one.' });
    }

    // Check if OTP matches
    if (user.emailOTP !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    // Mark as verified and clear OTP fields
    user.isEmailVerified = true;
    user.emailOTP = undefined;
    user.emailOTPExpiry = undefined;
    await user.save();

    res.json({ success: true, message: 'Email verified successfully!' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// RESEND OTP
// ─────────────────────────────────────────────
router.post('/resend-otp', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'User not found' });
    }

    if (user.isEmailVerified) {
      return res.status(400).json({ success: false, message: 'Email already verified' });
    }

    const otp = generateOTP();
    user.emailOTP = otp;
    user.emailOTPExpiry = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    await sendEmail({
      to: email,
      subject: 'SecureAuth — New Verification Code',
      html: otpEmailTemplate(otp)
    });

    res.json({ success: true, message: 'New OTP sent!' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────────
// What happens:
//   1. Check credentials
//   2. If 2FA enabled → return flag (frontend shows 2FA screen)
//   3. If 2FA disabled → return tokens immediately
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password required' });
    }

    const user = await User.findOne({ email });

    // ── Account Lock Check ──
    if (user && user.isLocked()) {
      return res.status(401).json({
        success: false,
        message: 'Account locked. Try again later.',
        lockedUntil: user.lockUntil
      });
    }

    // ── Check email exists AND password matches ──
    if (!user || !(await user.comparePassword(password))) {
      // Track failed attempts
      if (user) {
        user.loginAttempts += 1;
        if (user.loginAttempts >= 5) {
          // Lock for 30 minutes after 5 failed attempts
          user.lockUntil = new Date(Date.now() + 30 * 60 * 1000);
        }
        await user.save();
      }
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    // ── Check email is verified ──
    if (!user.isEmailVerified) {
      return res.status(401).json({
        success: false,
        message: 'Please verify your email first.',
        needsVerification: true
      });
    }

    // ── Reset login attempts on success ──
    user.loginAttempts = 0;
    user.lockUntil = undefined;

    // ── 2FA Check ──
    if (user.twoFactorEnabled) {
      // Don't give tokens yet! User must verify 2FA first.
      // We save a temporary token so we know WHO is trying to log in
      const tempToken = jwt.sign(
        { id: user._id, type: 'temp_2fa' },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: '5m' }
      );
      await user.save();
      return res.json({
        success: true,
        message: '2FA required',
        requires2FA: true,
        tempToken: tempToken
      });
    }

    // ── Generate Tokens ──
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);
    user.refreshToken = refreshToken;
    await user.save();

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: user.toJSON(),
        accessToken,
        refreshToken
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// REFRESH TOKEN
// ─────────────────────────────────────────────
// When access token expires, frontend sends refresh token here
// to get a NEW access token without logging in again
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ success: false, message: 'Refresh token required' });
    }

    // Verify the refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.id);

    // Make sure the refresh token in DB matches what was sent
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }

    // Issue a new access token
    const accessToken = generateAccessToken(user._id);

    res.json({ success: true, accessToken });
  } catch (err) {
    res.status(401).json({ success: false, message: 'Invalid or expired refresh token' });
  }
});

// ─────────────────────────────────────────────
// LOGOUT
// ─────────────────────────────────────────────
// We invalidate the refresh token in the DB
router.post('/logout', protect, async (req, res) => {
  try {
    req.user.refreshToken = undefined;
    await req.user.save();
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// FORGOT PASSWORD
// ─────────────────────────────────────────────
// Step 1 of password reset: Send a reset link via email
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    // IMPORTANT SECURITY: Always return success even if email doesn't exist
    // This prevents attackers from knowing which emails are registered
    if (!user) {
      return res.json({ success: true, message: 'If this email exists, you will receive a reset link.' });
    }

    // Generate a random token and hash it before storing
    const resetToken = crypto.randomBytes(20).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    user.passwordResetToken = hashedToken;
    user.passwordResetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    await user.save();

    // The link includes the UN-hashed token (only the user will see this)
    const resetLink = `http://localhost:3000/reset-password?token=${resetToken}&email=${email}`;

    await sendEmail({
      to: email,
      subject: 'SecureAuth — Reset Your Password',
      html: resetPasswordEmailTemplate(resetLink)
    });

    res.json({ success: true, message: 'If this email exists, you will receive a reset link.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// RESET PASSWORD
// ─────────────────────────────────────────────
// Step 2: User clicks the link and submits a new password
router.post('/reset-password', async (req, res) => {
  try {
    const { token, email, password } = req.body;

    // Hash the incoming token and compare with DB
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      email,
      passwordResetToken: hashedToken,
      passwordResetExpiry: { $gt: Date.now() } // Must not be expired
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired reset link' });
    }

    // Password strength check again
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        success: false,
        message: 'Password must be 8+ characters with uppercase, lowercase, number, and special character'
      });
    }

    // Update password and clear reset fields
    user.password = password; // pre-save hook will hash this!
    user.passwordResetToken = undefined;
    user.passwordResetExpiry = undefined;
    await user.save();

    res.json({ success: true, message: 'Password reset successfully!' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// 2FA SETUP (Generate QR Code)
// ─────────────────────────────────────────────
// Generates a secret + QR code for Google Authenticator
router.post('/2fa/setup', protect, async (req, res) => {
  try {
    // Generate a random secret
    const secret = speakeasy.generateSecret({ length: 20 });

    // Create a "provisioning URI" — this is what goes into the QR code
    // Format: otpauth://totp/AppName:email?secret=SECRET&issuer=AppName
    const otpauth = `otpauth://totp/SecureAuth:${req.user.email}?secret=${secret.base32}&issuer=SecureAuth`;

    // Generate QR code as a base64 data URI (can be put directly in <img>)
    const qrCodeDataURI = await QRCode.toDataURL(otpauth);

    // Store secret TEMPORARILY (not enabled yet until user verifies)
    req.user.twoFactorSecret = secret.base32;
    await req.user.save();

    res.json({
      success: true,
      data: {
        qrCode: qrCodeDataURI,
        secret: secret.base32  // Backup code in case QR scan fails
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// 2FA ENABLE (Confirm setup with a code)
// ─────────────────────────────────────────────
router.post('/2fa/enable', protect, async (req, res) => {
  try {
    const { code } = req.body;

    if (!req.user.twoFactorSecret) {
      return res.status(400).json({ success: false, message: 'No 2FA setup in progress' });
    }

    // Verify the code the user typed against our secret
    const isValid = speakeasy.totp.verify({
      secret: req.user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 1  // Allow 1 time-step before/after (30s tolerance)
    });

    if (!isValid) {
      return res.status(400).json({ success: false, message: 'Invalid code' });
    }

    // Now officially enable 2FA
    req.user.twoFactorEnabled = true;
    await req.user.save();

    res.json({ success: true, message: '2FA enabled successfully!' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// 2FA VERIFY (During login)
// ─────────────────────────────────────────────
router.post('/2fa/verify', async (req, res) => {
  try {
    const { tempToken, code } = req.body;

    // Verify the temp token to get the user
    const decoded = jwt.verify(tempToken, process.env.JWT_ACCESS_SECRET);
    if (decoded.type !== 'temp_2fa') {
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }

    const user = await User.findById(decoded.id);
    if (!user || !user.twoFactorEnabled) {
      return res.status(401).json({ success: false, message: 'Invalid request' });
    }

    // Verify the TOTP code
    const isValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 1
    });

    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Invalid 2FA code' });
    }

    // 2FA passed! Now issue real tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);
    user.refreshToken = refreshToken;
    await user.save();

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: user.toJSON(),
        accessToken,
        refreshToken
      }
    });
  } catch (err) {
    res.status(401).json({ success: false, message: 'Invalid or expired 2FA session' });
  }
});

module.exports = router;
