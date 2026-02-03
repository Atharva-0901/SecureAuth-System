# 🛡️ SecureAuth — Advanced Authentication System

## 📂 Project Structure (What Each File Does)

```
secure-auth-system/
├── server.js                 ← Main entry point. Starts the server.
├── package.json              ← Lists all dependencies (libraries).
├── .env.example              ← Template for your secret variables.
├── .gitignore                ← Tells git what to ignore.
│
├── models/
│   └── User.js               ← Defines what a User looks like in the database.
│
├── middleware/
│   └── auth.js               ← Checks if a user is logged in (JWT guard).
│
├── routes/
│   ├── authRoutes.js         ← All login/register/2FA endpoints.
│   └── profileRoutes.js      ← Profile & 2FA disable endpoint.
│
├── utils/
│   └── helpers.js            ← Reusable functions (tokens, OTP, email).
│
└── public/
    └── index.html            ← The entire frontend (Single Page App).
```

---

## 🧠 What Security Concepts This Project Teaches

| Concept | What It Is | Where In Code |
|---|---|---|
| **Password Hashing** | Passwords are NEVER stored in plain text. bcrypt transforms them into unreadable strings. | `models/User.js` → `pre('save')` |
| **JWT (Access Token)** | A short-lived (15 min) signed token proving who you are. Sent in every API request. | `utils/helpers.js` → `generateAccessToken` |
| **JWT (Refresh Token)** | A long-lived (7 days) token that silently gets you a new Access Token when it expires. | `routes/authRoutes.js` → `/refresh` |
| **Rate Limiting** | Blocks IPs that make too many requests (prevents brute force attacks). | `server.js` → `rateLimit` |
| **Account Lockout** | After 5 wrong password attempts, the account locks for 30 minutes. | `routes/authRoutes.js` → `/login` |
| **Email OTP Verification** | A 6-digit code is sent to your email to prove you own it. | `routes/authRoutes.js` → `/verify-otp` |
| **TOTP 2FA** | Uses Google Authenticator to generate time-based codes as a second login step. | `routes/authRoutes.js` → `/2fa/*` |
| **Password Reset** | A hashed token is sent via email. Only the token holder can reset the password. | `routes/authRoutes.js` → `/forgot-password` |
| **Helmet** | Automatically adds 15+ security HTTP headers to prevent XSS, clickjacking, etc. | `server.js` → `helmet()` |
| **Token in Memory Only** | Tokens are NEVER stored in localStorage (vulnerable to XSS). Kept in JS memory. | `public/index.html` → `state` object |

---

## ⚡ Step-by-Step Setup Guide

### Step 1: Install Node.js

Download and install Node.js from: **https://nodejs.org**
- Choose the **LTS** (Long Term Support) version.
- After installing, verify it worked by opening your terminal and typing:
  ```
  node --version
  npm --version
  ```
  You should see version numbers like `v20.x.x` and `10.x.x`.

---

### Step 2: Install MongoDB

You need a database to store users. MongoDB is a free, flexible database.

**Option A — Use MongoDB Atlas (Cloud, Recommended for Beginners):**
1. Go to **https://www.mongodb.com/cloud/atlas**
2. Create a free account.
3. Click **"Build a database"** → choose **Free** tier.
4. Choose a region close to you.
5. Create a username and password (save these!).
6. Under **"IP Address"**, click **"Add Current IP Address"**.
7. Click **"Get Started"** → choose **"Browse Collections"**.
8. Click **"Connect"** → **"Connect your application"** → **"Node.js"**.
9. Copy the connection string. It looks like:
   ```
   mongodb+srv://youruser:yourpass@cluster.mongodb.net/mydb?retryWrites=true&w=majority
   ```
   This is what goes into your `.env` file as `MONGODB_URI`.

**Option B — Install MongoDB Locally:**
1. Go to **https://www.mongodb.com/docs/manual/installation/**
2. Follow the guide for your operating system.
3. Your URI will be: `mongodb://localhost:27017/secure_auth_db`

---

### Step 3: Set Up Gmail for Sending Emails

Our app sends real verification emails. Here's how to set it up:

1. Go to your **Gmail** account.
2. Click your profile picture → **"Manage your Google Account"**.
3. Go to **"Security"** tab.
4. Enable **"2-Step Verification"** (if not already on).
5. Scroll down and click **"App passwords"**.
6. Choose **App: Mail**, **Device: Windows Computer** (or your OS).
7. Click **"Generate"** → Copy the 16-character password.
8. This 16-character code is your `EMAIL_PASS` in `.env`.

---

### Step 4: Clone / Download the Project

If you have the project files, put them in a folder. Open your **terminal** (or Command Prompt on Windows) and navigate into that folder:
```bash
cd path/to/secure-auth-system
```

---

### Step 5: Install Dependencies

This downloads all the libraries (express, bcrypt, etc.) listed in `package.json`:
```bash
npm install
```
This creates a `node_modules/` folder. This can take a minute. Do NOT touch it.

---

### Step 6: Create Your `.env` File

1. Copy `.env.example` and rename it to `.env` (just `.env`, no other name).
2. Open `.env` in any text editor.
3. Fill in the values:

```
MONGODB_URI=mongodb+srv://youruser:yourpass@cluster.mongodb.net/mydb
JWT_ACCESS_SECRET=make_this_a_long_random_string_like_this_abc123xyz789
JWT_REFRESH_SECRET=another_different_long_random_string_here_def456uvw012
JWT_ACCESS_EXPIRES=15m
JWT_REFRESH_EXPIRES=7d
EMAIL_USER=youremail@gmail.com
EMAIL_PASS=your16charapppassword
PORT=5000
```

**IMPORTANT:** Never share your `.env` file with anyone. It contains secrets!

---

### Step 7: Start the Backend Server

```bash
npm run dev
```
You should see:
```
🚀 Server running on http://localhost:5000
✅ Connected to MongoDB
```

If you see a MongoDB error, double-check your `MONGODB_URI` in `.env`.

---

### Step 8: Open the Frontend

Open the file `public/index.html` in your web browser.
- You can double-click it in your file explorer.
- OR use a live server extension in VS Code (recommended!).

**VS Code Live Server Setup:**
1. Install VS Code: **https://code.visualstudio.com**
2. Open the project folder in VS Code.
3. Install the extension: **"Live Server"** (by Ritwick Dey).
4. Right-click `public/index.html` → **"Go Live"**.
5. It opens at `http://127.0.0.1:5500/public/index.html`.

> **Note:** If using Live Server, update the CORS origin in `server.js` to `http://127.0.0.1:5500` instead of `http://localhost:3000`.

---

### Step 9: Test the App!

1. **Register** → Fill in name, email, password (must be strong!).
2. **Check your Gmail** → You'll receive a 6-digit code.
3. **Enter the OTP** → Your email is verified!
4. **Login** → Enter your email and password.
5. **Dashboard** → See your security status.
6. **Setup 2FA** → Scan the QR code with Google Authenticator → Enter the code → 2FA is ON!
7. **Logout and Login again** → Now it asks for your 2FA code!
8. **Forgot Password** → Enter your email → Check Gmail for reset link.

---

## 🔧 How to Use `nodemon` (Auto-Restart)

When you change backend code, you normally have to restart the server manually.
`nodemon` watches for changes and restarts automatically.

- `npm run dev` uses nodemon (already set up in package.json).
- `npm start` uses regular node (no auto-restart).

---

## 🛡️ Security Features Checklist

- [x] Passwords hashed with bcrypt (salt rounds: 12)
- [x] JWT access + refresh token system
- [x] Rate limiting on all routes (100/15min)
- [x] Stricter rate limiting on auth routes (10/15min)
- [x] Account lockout after 5 failed login attempts (30 min lock)
- [x] Email OTP verification (expires in 10 minutes)
- [x] TOTP Two-Factor Authentication (Google Authenticator)
- [x] Password reset with hashed tokens (expires in 1 hour)
- [x] Helmet security headers
- [x] Sensitive data never sent to frontend (toJSON filter)
- [x] Tokens stored in memory only (not localStorage)
- [x] Password strength validation (regex)
- [x] CORS restricted to frontend origin only

---
