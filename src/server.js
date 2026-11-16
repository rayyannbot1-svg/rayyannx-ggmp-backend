require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();

app.disable("x-powered-by");
app.use(helmet());

const allowedOrigins = process.env.CORS_ORIGIN;

app.use(cors({
  origin: !allowedOrigins || allowedOrigins === "*"
    ? true
    : allowedOrigins.split(",").map(s => s.trim()),
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "apikey",
    "x-admin-key"
  ]
}));

app.use(express.json({ limit: "20kb" }));

// Environment configuration
const required = [
  "SUPABASE_URL",
  "SUPABASE_SECRET_KEY",
  "JWT_SECRET"
];

const missing = required.filter(key => !process.env[key]);

if (missing.length) {
  console.error("Missing environment variables:", missing.join(", "));
  process.exit(1);
}

if (process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters.");
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

// Login rate limit
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    success: false,
    code: "TOO_MANY_ATTEMPTS",
    message: "Terlalu banyak percobaan. Coba lagi 15 menit."
  }
});

// Health endpoints
app.get("/", (_req, res) => {
  res.json({
    success: true,
    service: "RayyannX GGMP API",
    status: "online"
  });
});

app.get("/health", (_req, res) => {
  res.json({
    success: true,
    status: "ok"
  });
});

// Login endpoint
app.post("/auth/login", loginLimiter, async (req, res) => {
  try {
    const username = String(req.body?.username ?? "").trim();
    const password = String(req.body?.password ?? "");
    const licenseKey = String(
      req.body?.licenseKey ?? req.body?.license_key ?? ""
    ).trim();

    if (!username || !password || !licenseKey) {
      return res.status(400).json({
        success: false,
        code: "MISSING_FIELDS",
        message: "Username, password, dan License Key wajib diisi."
      });
    }

    const { data: user, error: userError } = await supabase
      .from("users")
      .select("id, username, password_hash, is_active")
      .eq("username", username)
      .maybeSingle();

    if (userError) throw userError;

    if (
      !user ||
      !(await bcrypt.compare(password, user.password_hash || ""))
    ) {
      return res.status(401).json({
        success: false,
        code: "INVALID_CREDENTIALS",
        message: "Username atau password salah."
      });
    }

    if (user.is_active !== true) {
      return res.status(403).json({
        success: false,
        code: "ACCOUNT_INACTIVE",
        message: "Akun tidak aktif."
      });
    }

    const { data: license, error: licenseError } = await supabase
      .from("license_keys")
      .select("id, key, user_id, is_active, expires_at")
      .eq("key", licenseKey)
      .eq("user_id", user.id)
      .maybeSingle();

    if (licenseError) throw licenseError;

    if (!license || license.is_active !== true) {
      return res.status(403).json({
        success: false,
        code: "INVALID_LICENSE",
        message: "License Key tidak valid atau tidak aktif."
      });
    }

    if (
      license.expires_at &&
      new Date(license.expires_at).getTime() <= Date.now()
    ) {
      return res.status(403).json({
        success: false,
        code: "LICENSE_EXPIRED",
        message: "License Key sudah kedaluwarsa."
      });
    }

    const token = jwt.sign(
      {
        sub: String(user.id),
        username: user.username,
        licenseId: license.id,
        plan: "PREMIUM"
      },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRES_IN || "12h",
        issuer: "rayyannx-ggmp"
      }
    );

    return res.json({
      success: true,
      status: "PREMIUM",
      message: "Login berhasil.",
      token,
      user: {
        id: user.id,
        username: user.username,
        plan: "PREMIUM"
      },
      license: {
        expiresAt: license.expires_at || null
      }
    });

  } catch (error) {
    console.error("Login error:", error.message || error);

    return res.status(500).json({
      success: false,
      code: "SERVER_ERROR",
      message: "Terjadi kesalahan server."
    });
  }
});

// ADMIN: Create user and license
app.post("/admin/users", async (req, res) => {
  try {
    const adminKey = req.headers["x-admin-key"] || "";
    const expectedKey = process.env.ADMIN_API_KEY || "";

    if (!expectedKey || adminKey !== expectedKey) {
      return res.status(401).json({
        success: false,
        message: "Akses Admin ditolak."
      });
    }

    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    const days = req.body?.expiresInDays;

    if (!username || password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Username wajib diisi dan password minimal 8 karakter."
      });
    }

    if (
      days !== undefined &&
      (!Number.isInteger(days) || days < 1)
    ) {
      return res.status(400).json({
        success: false,
        message: "Masa aktif harus berupa jumlah hari minimal 1."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { data: user, error: userError } = await supabase
      .from("users")
      .insert({
        username,
        password_hash: passwordHash,
        is_active: true
      })
      .select("id, username")
      .single();

    if (userError) throw userError;

    const licenseKey =
      "RX-" + crypto.randomBytes(12).toString("hex").toUpperCase();

    const expiresAt = days
      ? new Date(Date.now() + days * 86400000).toISOString()
      : null;

    const { error: licenseError } = await supabase
      .from("license_keys")
      .insert({
        key: licenseKey,
        user_id: user.id,
        is_active: true,
        expires_at: expiresAt
      });

    if (licenseError) {
      await supabase.from("users").delete().eq("id", user.id);
      throw licenseError;
    }

    return res.json({
      success: true,
      message: "Akun PREMIUM berhasil dibuat.",
      user,
      licenseKey,
      expiresAt
    });

  } catch (error) {
    console.error("Admin create user error:", error.message || error);

    return res.status(500).json({
      success: false,
      message: "Gagal membuat akun."
    });
  }
});

// Verify token
app.get("/auth/me", (req, res) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Token tidak ditemukan."
    });
  }

  try {
    const payload = jwt.verify(
      token,
      process.env.JWT_SECRET,
      { issuer: "rayyannx-ggmp" }
    );

    return res.json({
      success: true,
      status: "PREMIUM",
      user: {
        id: payload.sub,
        username: payload.username
      }
    });

  } catch {
    return res.status(401).json({
      success: false,
      message: "Token tidak valid atau kedaluwarsa."
    });
  }
});

// Logout
app.post("/auth/logout", (_req, res) => {
  return res.json({
    success: true,
    message: "Logout berhasil. Hapus token dari perangkat."
  });
});

// Start server
const PORT = Number(process.env.PORT || 3000);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`RayyannX GGMP API listening on port ${PORT}`);
});
    
      

