// ============================================
// routes/profileRoutes.js — USER PROFILE ROUTES
// ============================================


const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/auth');
const User = require('../models/User');

// ─────────────────────────────────────────────
// GET PROFILE
// ─────────────────────────────────────────────

router.get('/me', protect, async (req, res) => {
  res.json({
    success: true,
    data: {
      user: req.user.toJSON(),

      twoFactorEnabled: req.user.twoFactorEnabled,
      isEmailVerified: req.user.isEmailVerified
    }
  });
});

// ─────────────────────────────────────────────
// UPDATE PROFILE
// ─────────────────────────────────────────────

router.put('/me', protect, async (req, res) => {
  try {
    const { name } = req.body;

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ success: false, message: 'Name is required' });
    }

    req.user.name = name.trim();
    await req.user.save();

    res.json({
      success: true,
      message: 'Profile updated!',
      data: { user: req.user.toJSON() }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─────────────────────────────────────────────
// DISABLE 2FA
// ─────────────────────────────────────────────

router.post('/2fa/disable', protect, async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ success: false, message: 'Password is required to disable 2FA' });
    }


    const user = await User.findById(req.user._id);
    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Incorrect password' });
    }

    user.twoFactorEnabled = false;
    user.twoFactorSecret = undefined;
    await user.save();

    res.json({ success: true, message: '2FA has been disabled.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

module.exports = router;
