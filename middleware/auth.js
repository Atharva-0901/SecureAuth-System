// ============================================
// middleware/auth.js — JWT AUTHENTICATION GUARD
// ============================================
// This middleware runs BEFORE your route handlers.
// It checks: "Does this person have a valid token?"
// If yes → let them through. If no → block them.
//
// Usage in routes:
//   router.get('/protected', protect, (req, res) => { ... });
//   The word "protect" here is this middleware.

const jwt = require('jsonwebtoken');
const User = require('../models/User');

const protect = async (req, res, next) => {
  let token;

  // ─── Step 1: Get the token ─────────────────
  // We look for it in the Authorization header
  // Format: "Bearer eyJhbGciOi..."
  // "Bearer" is just a prefix/label we agreed on
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer')) {
    token = authHeader.split(' ')[1]; // Get everything after "Bearer "
  }

  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  try {
    // ─── Step 2: Verify the token ────────────
    // jwt.verify() checks:
    //   1. Was this token signed with our secret? (not tampered)
    //   2. Has it expired?
    // If both pass, it returns the PAYLOAD (the data we put inside)
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    // ─── Step 3: Attach user to the request ──
    // We fetch the user from DB (minus password) and attach to req
    // Now any route handler can access req.user
    req.user = await User.findById(decoded.id).select('-password');

    if (!req.user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    next(); // ✅ Everything is good, move to the next middleware/route
  } catch (err) {
    // Token is invalid or expired
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
};

module.exports = { protect };
