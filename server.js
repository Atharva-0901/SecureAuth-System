require('dns').setDefaultResultOrder('ipv4first');

const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']); 
if (dns.setDefaultResultOrder) { dns.setDefaultResultOrder('ipv4first'); }

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/authRoutes');
const profileRoutes = require('./routes/profileRoutes');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(helmet());
app.use(cors({ origin: 'http://127.0.0.1:5500', credentials: true }));
app.use(express.json());

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Too many attempts.' }
});

app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/profile', profileRoutes);

// MongoDB Connection String (SRV format with correct password)
const MONGODB_URI = "mongodb+srv://atharva0901:b7NQn4Xk0ryQwsRx@cluster0.dygyesx.mongodb.net/secure_auth_db?retryWrites=true&w=majority";

// Connect to MongoDB
mongoose.connect(MONGODB_URI, {
    family: 4,                       // Force IPv4
    serverSelectionTimeoutMS: 10000, // 10 second timeout
    socketTimeoutMS: 45000,
    connectTimeoutMS: 10000
})
.then(() => {
    console.log('-------------------------------------------');
    console.log('✅ TEAM NULL: DATABASE ONLINE');
    console.log('-------------------------------------------');
})
.catch(err => {
    console.error('❌ CONNECTION ERROR:', err.message);
});

app.listen(PORT, () => {
    console.log(`🚀 Server: http://localhost:${PORT}`);
});