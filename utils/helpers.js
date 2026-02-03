// ============================================
// utils/helpers.js — REUSABLE HELPER FUNCTIONS
// ============================================
// These are small, reusable tools used across the project.
// Think of them as utility functions in a toolbox.

const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto'); // Node.js built-in for random numbers

// ─────────────────────────────────────────────
// 1. GENERATE JWT TOKENS
// ─────────────────────────────────────────────
// We use TWO tokens:
//   - Access Token:  Short-lived (15 min). Used to access data.
//   - Refresh Token: Long-lived (7 days). Used to GET a new Access Token.
// This way, even if an Access Token is stolen, it expires quickly.

const generateAccessToken = (userId) => {
  return jwt.sign(
    { id: userId },                          // PAYLOAD: data stored in token
    process.env.JWT_ACCESS_SECRET,            // SECRET: signs the token
    { expiresIn: process.env.JWT_ACCESS_EXPIRES || '15m' } // EXPIRY
  );
};

const generateRefreshToken = (userId) => {
  return jwt.sign(
    { id: userId },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES || '7d' }
  );
};

// ─────────────────────────────────────────────
// 2. GENERATE A RANDOM 6-DIGIT OTP
// ─────────────────────────────────────────────
// crypto.randomInt() gives a cryptographically secure random number
// This is MUCH better than Math.random() for security!
const generateOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

// ─────────────────────────────────────────────
// 3. SEND EMAIL USING NODEMAILER
// ─────────────────────────────────────────────
// Nodemailer lets us send real emails from Node.js
// We configure it with Gmail credentials (from .env)

const sendEmail = async ({ to, subject, html }) => {
  // Create a "transporter" — this is the email sender
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,                  // Use TLS (not SSL)
    auth: {
      user: process.env.EMAIL_USER, // Your Gmail address
      pass: process.env.EMAIL_PASS  // Your App Password
    }
  });

  // Send the actual email
  await transporter.sendMail({
    from: `"SecureAuth" <${process.env.EMAIL_USER}>`,
    to: to,
    subject: subject,
    html: html                      // We send HTML emails (styled!)
  });
};

// ─────────────────────────────────────────────
// 4. EMAIL TEMPLATES
// ─────────────────────────────────────────────
// These return styled HTML strings for our emails

const otpEmailTemplate = (otp) => `
  <div style="font-family: 'Segoe UI', sans-serif; max-width: 480px; margin: 0 auto; background: #0f172a; color: #e2e8f0; padding: 40px 32px; border-radius: 16px; border: 1px solid #1e293b;">
    <h2 style="color: #38bdf8; text-align: center; margin-top: 0;">🔐 Verification Code</h2>
    <p style="text-align: center; color: #94a3b8;">Enter this code to verify your email address</p>
    <div style="text-align: center; background: #1e293b; border-radius: 12px; padding: 24px; margin: 24px 0; border: 1px solid #334155;">
      <span style="font-size: 36px; font-weight: 700; letter-spacing: 12px; color: #38bdf8;">${otp}</span>
    </div>
    <p style="text-align: center; color: #64748b; font-size: 13px;">This code expires in 10 minutes. Do not share it with anyone.</p>
  </div>
`;

const resetPasswordEmailTemplate = (resetLink) => `
  <div style="font-family: 'Segoe UI', sans-serif; max-width: 480px; margin: 0 auto; background: #0f172a; color: #e2e8f0; padding: 40px 32px; border-radius: 16px; border: 1px solid #1e293b;">
    <h2 style="color: #f472b6; text-align: center; margin-top: 0;">🔑 Password Reset</h2>
    <p style="text-align: center; color: #94a3b8;">Click the button below to reset your password</p>
    <div style="text-align: center; margin: 32px 0;">
      <a href="${resetLink}" style="background: linear-gradient(135deg, #38bdf8, #818cf8); color: #fff; padding: 14px 32px; border-radius: 8px; text-decoration: none; font-weight: 600; display: inline-block;">Reset Password</a>
    </div>
    <p style="text-align: center; color: #64748b; font-size: 13px;">This link expires in 1 hour. If you didn't request this, ignore this email.</p>
  </div>
`;

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  generateOTP,
  sendEmail,
  otpEmailTemplate,
  resetPasswordEmailTemplate
};
