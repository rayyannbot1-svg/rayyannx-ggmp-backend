
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 8080;

const requiredEnv = [
  "SUPABASE_URL",
  "SUPABASE_SECRET_KEY",
  "JWT_SECRET"
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(`Missing environment variable: ${key}`);
    process.exit(1);
  }
}

if (process.env.JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters");
  process.exit(1);
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

app.use(helmet());
app.use(cors());
app.use(express.json());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

function isExpired(date) {
  return date && new Date(date).getTime() <= Date.now();
}

function createToken(user) {
  return jwt.sign(
    { userId: user.id },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "RayyannX GGMP Backend is running"
  });
});

app.post("/auth/login", loginLimiter, async (req, res) => {
  try {
    const { username, password, licenseKey } = req.body;

    if (!username || !password || !licenseKey) {
      return res.status(400).json({
        success: false,
        message: "Username, password, and license key are required"
      });
    }

    const { data: user, error: userError } = await supabase
      .from("users")
      .select("id, username, password_hash, status, premium, premium_expires_at")
      .eq("username", username)
      .maybeSingle();

    if (userError) throw userError;

    if (!user || user.status !== "ACTIVE") {
      return res.status(401).json({
        success: false,
        message: "Invalid account or inactive account"
      });
    }

    const passwordValid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordValid) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password"
      });
    }

    const { data: license, error: licenseError } = await supabase
      .from("license_keys")
      .select("id, license_key, user_id, status, expires_at")
      .eq("license_key", licenseKey)
      .eq("user_id", user.id)
      .maybeSingle();

    if (licenseError) throw licenseError;

    if (
      !license ||
      license.status !== "ACTIVE" ||
      isExpired(license.expires_at)
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid, inactive, or expired license key"
      });
    }

    if (
      !user.premium ||
      isExpired(user.premium_expires_at)
    ) {
      return res.status(403).json({
        success: false,
        message: "Premium access is inactive or expired"
      });
    }

    const token = createToken(user);

    return res.json({
      success: true,
      status: "PREMIUM",
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
        premium: true
      }
    });

  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

app.get("/auth/me", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication required"
      });
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const { data: user, error } = await supabase
      .from("users")
      .select("id, username, status, premium, premium_expires_at")
      .eq("id", decoded.userId)
      .maybeSingle();

    if (error) throw error;

    if (
      !user ||
      user.status !== "ACTIVE" ||
      !user.premium ||
      isExpired(user.premium_expires_at)
    ) {
      return res.status(401).json({
        success: false,
        message: "Account inactive or expired"
      });
    }

    return res.json({
      success: true,
      status: "PREMIUM",
      user: {
        id: user.id,
        username: user.username,
        premium: true
      }
    });

  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token"
    });
  }
});

app.post("/auth/logout", (req, res) => {
  res.json({
    success: true,
    message: "Logout successful"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`RayyannX GGMP Backend running on port ${PORT}`);
});
