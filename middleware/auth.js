// ============================================
// middleware/auth.js — JWT AUTHENTICATION GUARD
// ============================================


const jwt = require('jsonwebtoken');
const User = require('../models/User');

const protect = async (req, res, next) => {
  let token;

  // ─── Step 1: Get the token ─────────────────

  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer')) {
    token = authHeader.split(' ')[1]; 
  }

  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  try {
    // ─── Step 2: Verify the token ────────────

    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    // ─── Step 3: Attach user to the request ──

    req.user = await User.findById(decoded.id).select('-password');

    if (!req.user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    next();
  } catch (err) {

    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
};

module.exports = { protect };
