require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.disable("x-powered-by");
app.use(helmet());
app.use(cors({
origin: process.env.CORS_ORIGIN === "*" ? true : (process.env.CORS_ORIGIN || "").split(",").map(s => s.trim()),
methods: ["GET", "POST", "OPTIONS"],
allowedHeaders: ["Content-Type", "Authorization", "apikey"]
}));
app.use(express.json({ limit: "20kb" }));

const required = ["SUPABASE_URL", "SUPABASE_SECRET_KEY", "JWT_SECRET"];
const missing = required.filter(k => !process.env[k]);
if (missing.length) {
console.error("Missing environment variables:", missing.join(", "));
process.exit(1);
}
if (process.env.JWT_SECRET.length < 32) {
console.error("JWT_SECRET must be at least 32 characters.");
process.exit(1);
}

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
auth: { persistSession: false, autoRefreshToken: false }
});

const loginLimiter = rateLimit({
windowMs: 15 * 60 * 1000,
limit: 10,
standardHeaders: "draft-8",
legacyHeaders: false,
message: { success: false, code: "TOO_MANY_ATTEMPTS", message: "Terlalu banyak percobaan. Coba lagi 15 menit." }
});

app.get("/", (_req, res) => res.json({ success: true, service: "RayyannX GGMP API", status: "online" }));
app.get("/health", (_req, res) => res.json({ success: true, status: "ok" }));

app.post("/auth/login", loginLimiter, async (req, res) => {
try {
const username = String(req.body?.username ?? "").trim();
const password = String(req.body?.password ?? "");
const licenseKey = String(req.body?.licenseKey ?? req.body?.license_key ?? "").trim();

if (!username || !password || !licenseKey) {  
  return res.status(400).json({  
    success: false, code: "MISSING_FIELDS",  
    message: "Username, password, dan License Key wajib diisi."  
  });  
}  

// Expected schema: public.users(username, password_hash, is_active, id)  
const { data: user, error: userError } = await supabase  
  .from("users")  
  .select("id, username, password_hash, is_active")  
  .eq("username", username)  
  .maybeSingle();  

if (userError) throw userError;  
if (!user || !(await bcrypt.compare(password, user.password_hash || ""))) {  
  return res.status(401).json({  
    success: false, code: "INVALID_CREDENTIALS",  
    message: "Username atau password salah."  
  });  
}  
if (user.is_active === false) {  
  return res.status(403).json({  
    success: false, code: "ACCOUNT_INACTIVE",  
    message: "Akun tidak aktif. Hubungi administrator."  
  });  
}  

// Expected schema: public.license_keys(key, user_id, is_active, expires_at)  
const { data: license, error: licenseError } = await supabase  
  .from("license_keys")  
  .select("id, key, user_id, is_active, expires_at")  
  .eq("key", licenseKey)  
  .eq("user_id", user.id)  
  .maybeSingle();  

if (licenseError) throw licenseError;  
if (!license || license.is_active === false) {  
  return res.status(403).json({  
    success: false, code: "INVALID_LICENSE",  
    message: "License Key tidak valid atau tidak aktif."  
  });  
}  
if (license.expires_at && new Date(license.expires_at).getTime() <= Date.now()) {  
  return res.status(403).json({  
    success: false, code: "LICENSE_EXPIRED",  
    message: "License Key sudah kedaluwarsa."  
  });  
}  

const token = jwt.sign(  
  { sub: String(user.id), username: user.username, licenseId: license.id, plan: "PREMIUM" },  
  process.env.JWT_SECRET,  
  { expiresIn: process.env.JWT_EXPIRES_IN || "12h", issuer: "rayyannx-ggmp" }  
);  

// Store a session record if the auth_sessions table has the expected columns.  
// Login remains successful if session logging is not configured yet.  
try {  
  await supabase.from("auth_sessions").insert({  
    user_id: user.id,  
    license_key_id: license.id,  
    token,  
    created_at: new Date().toISOString()  
  });  
} catch (sessionError) {  
  console.warn("Session insert skipped:", sessionError.message);  
}  

return res.json({  
  success: true,  
  status: "PREMIUM",  
  message: "Login berhasil.",  
  token,  
  user: { id: user.id, username: user.username, plan: "PREMIUM" },  
  license: { expiresAt: license.expires_at || null }  
});

} catch (error) {
console.error("Login error:", error.message || error);
return res.status(500).json({
success: false, code: "SERVER_ERROR",
message: "Terjadi kesalahan server. Periksa konfigurasi dan struktur tabel Supabase."
});
}
});

app.get("/auth/me", async (req, res) => {
const header = req.headers.authorization || "";
const token = header.startsWith("Bearer ") ? header.slice(7) : "";
if (!token) return res.status(401).json({ success: false, message: "Token tidak ditemukan." });
try {
const payload = jwt.verify(token, process.env.JWT_SECRET, { issuer: "rayyannx-ggmp" });
return res.json({ success: true, status: "PREMIUM", user: { id: payload.sub, username: payload.username } });
} catch {
return res.status(401).json({ success: false, message: "Token tidak valid atau kedaluwarsa." });
}
});

app.post("/auth/logout", (_req, res) => {
// JWT is stateless; the Android app must delete its locally stored token.
return res.json({ success: true, message: "Logout berhasil. Hapus token dari penyimpanan perangkat." });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(RayyannX GGMP API listening on port ${port}));
