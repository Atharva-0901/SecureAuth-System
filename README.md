# 🛡️ SecureAuth - Advanced Authentication System

**TEAM NULL** | Secure, Scalable, Production-Ready Authentication

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Node](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)
![MongoDB](https://img.shields.io/badge/mongodb-atlas-green.svg)

## 🚀 Features

- ✅ **Email Verification** with OTP (One-Time Password)
- ✅ **Two-Factor Authentication (2FA)** with QR code
- ✅ **JWT Token System** (Access + Refresh tokens)
- ✅ **Password Reset** with secure tokens
- ✅ **Rate Limiting** (Brute force protection)
- ✅ **Bcrypt Password Hashing**
- ✅ **CORS & Helmet Security**
- ✅ **Beautiful Animated Frontend**

## 🛠️ Tech Stack

**Backend:**
- Node.js + Express.js
- MongoDB Atlas (Cloud Database)
- Mongoose ODM
- JWT (JSON Web Tokens)
- Bcrypt (Password Hashing)
- Nodemailer (Email Service)
- Speakeasy (2FA/TOTP)

**Frontend:**
- Vanilla JavaScript (No frameworks!)
- HTML5 + CSS3
- Advanced CSS Animations
- Responsive Design

## 📦 Installation

### 1. Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/SecureAuth-System.git
cd SecureAuth-System
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Setup Environment Variables
Create `.env` file:
```env
MONGODB_URI=your_mongodb_connection_string
JWT_ACCESS_SECRET=your_access_secret
JWT_REFRESH_SECRET=your_refresh_secret
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
PORT=5000
```

### 4. Run Server
```bash
npm run dev
```

Server starts at: `http://localhost:5000`

### 5. Open Frontend
Open `index.html` in browser or use Live Server

## 📂 Project Structure
```
SecureAuth-Project/
├── controllers/
│   ├── authController.js      # Authentication logic
│   └── profileController.js   # User profile logic
├── middleware/
│   ├── authMiddleware.js      # JWT verification
│   └── validation.js          # Input validation
├── models/
│   └── User.js                # MongoDB User schema
├── routes/
│   ├── authRoutes.js          # Auth endpoints
│   └── profileRoutes.js       # Profile endpoints
├── utils/
│   └── emailService.js        # Email sending
├── .env                        # Environment variables (DO NOT COMMIT!)
├── .gitignore                 # Git ignore rules
├── server.js                  # Entry point
├── package.json               # Dependencies
└── index.html                 # Frontend UI
```

## 🔐 Security Features

- ✅ **Bcrypt** password hashing with salt
- ✅ **JWT** with expiration (15 min access, 7 day refresh)
- ✅ **Rate limiting** (100 requests per 15 minutes)
- ✅ **CORS** protection
- ✅ **Helmet** security headers
- ✅ **Input validation** (express-validator)
- ✅ **OTP expiration** (10 minutes)
- ✅ **2FA** with time-based codes
- ✅ **Tokens stored in memory** (not localStorage)

## 📱 API Endpoints

### Authentication
```
POST   /api/auth/register       - Register new user
POST   /api/auth/verify-otp     - Verify email OTP
POST   /api/auth/resend-otp     - Resend OTP
POST   /api/auth/login          - Login user
POST   /api/auth/refresh        - Refresh access token
POST   /api/auth/logout         - Logout user
POST   /api/auth/forgot-password - Send reset link
POST   /api/auth/reset-password  - Reset password
```

### Two-Factor Authentication
```
POST   /api/auth/2fa/setup      - Generate QR code
POST   /api/auth/2fa/enable     - Enable 2FA
POST   /api/auth/2fa/verify     - Verify 2FA code (login)
```

### Profile (Protected)
```
POST   /api/profile/2fa/disable - Disable 2FA
```

## 🎨 Frontend Features

- ⚡ Smooth animations (fade, slide, scale, rotate)
- 🎯 OTP input with auto-focus
- 💪 Password strength meter
- 🔄 Auto-refresh token timer
- 📱 Fully responsive design
- 🌊 Gradient backgrounds with particles
- ✨ Interactive hover effects

## 👥 Team

**TEAM NULL** - Building Secure Systems

## 📄 License

MIT License - feel free to use for learning!

## 🤝 Contributing

Pull requests welcome! Please follow coding standards.

## 📧 Contact

For questions: aizen.ath0109@gmail.com

---

**⚡ TEAM NULL - Powered by Innovation ⚡**
