require("dotenv").config();
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const fs = require("fs");
const multer = require("multer");
const JOURNEY_MONTHS = require("./journey-db.js");
const app = express();
const { v4: uuidv4 } = require("uuid");

// Import database functions
const {
  supabase,
  getUserByEmail,
  getUserById,
  createUser,
  updateUser,
  deleteUser,
  listUsers,
  getJourneyProgress,
  upsertJourneyProgress,
  getAllJourneyProgress,
  getArticles,
  getArticleById,
  createArticle,
  updateArticle,
  deleteArticle,
  incrementArticleViews,
  getPosts,
  createPost,
  createSession: createSessionDB,
  getSession: getSessionDB,
  deleteSession: deleteSessionDB,
} = require("./models/db.js");

// ------------------------
// Basic Middleware
// ------------------------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Disable cache in development and simple request logging
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  console.log(`${req.method} ${req.url}`);
  next();
});

// Serve static assets
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ------------------------
// In-memory storage
// ------------------------
const ambassadorsByEmail = new Map();
const partnersByEmail = new Map();
const adminsByEmail = new Map();
const articlesById = new Map();
const notificationsByUserId = new Map();
const sessions = new Map();
const postsById = new Map();
const journeyProgressByAmbassador = new Map();

// ------------------------
// File-based persistence
// ------------------------
const DATA_DIR = path.join(__dirname, "data");
const ARTICLES_FILE = path.join(DATA_DIR, "articles.json");
const POSTS_FILE = path.join(DATA_DIR, "posts.json");
const JOURNEY_FILE = path.join(DATA_DIR, "journey.json");
const UPLOADS_DIR = path.join(__dirname, "uploads");
const CVS_DIR = path.join(UPLOADS_DIR, "cvs");

function ensureDataDir() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (!fs.existsSync(CVS_DIR)) {
      fs.mkdirSync(CVS_DIR, { recursive: true });
    }
  } catch (err) {
    console.warn(
      "[data] Failed to ensure data directory:",
      err && err.message ? err.message : err
    );
  }
}

function loadArticlesFromDisk() {
  try {
    ensureDataDir();
    if (!fs.existsSync(ARTICLES_FILE)) return;
    const raw = fs.readFileSync(ARTICLES_FILE, "utf8");
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      articlesById.clear();
      for (const art of parsed) {
        if (art && art.id) {
          articlesById.set(String(art.id), art);
        }
      }
      console.log(
        `[articles] Loaded ${articlesById.size} article(s) from disk`
      );
    }
  } catch (err) {
    console.warn(
      "[articles] Failed to load from disk:",
      err && err.message ? err.message : err
    );
  }
}

function saveArticlesToDisk() {
  try {
    ensureDataDir();
    const all = [...articlesById.values()];
    const json = JSON.stringify(all, null, 2);
    fs.writeFileSync(ARTICLES_FILE, json, "utf8");
  } catch (err) {
    console.warn(
      "[articles] Failed to save to disk:",
      err && err.message ? err.message : err
    );
  }
}

function loadPostsFromDisk() {
  try {
    ensureDataDir();
    if (!fs.existsSync(POSTS_FILE)) return;
    const raw = fs.readFileSync(POSTS_FILE, "utf8");
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      postsById.clear();
      for (const post of parsed) {
        if (post && post.id) {
          postsById.set(String(post.id), post);
        }
      }
      console.log(`[posts] Loaded ${postsById.size} post(s) from disk`);
    }
  } catch (err) {
    console.warn(
      "[posts] Failed to load from disk:",
      err && err.message ? err.message : err
    );
  }
}

function savePostsToDisk() {
  try {
    ensureDataDir();
    const all = [...postsById.values()];
    const json = JSON.stringify(all, null, 2);
    fs.writeFileSync(POSTS_FILE, json, "utf8");
    console.log(`[posts] Saved ${all.length} post(s) to disk`);
  } catch (err) {
    console.warn(
      "[posts] Failed to save to disk:",
      err && err.message ? err.message : err
    );
  }
}

function loadJourneyFromDisk() {
  try {
    ensureDataDir();
    if (!fs.existsSync(JOURNEY_FILE)) return;
    const raw = fs.readFileSync(JOURNEY_FILE, "utf8");
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (typeof parsed === "object") {
      journeyProgressByAmbassador.clear();
      for (const [ambassadorId, progress] of Object.entries(parsed)) {
        journeyProgressByAmbassador.set(ambassadorId, progress);
      }
      console.log(
        `[journey] Loaded ${journeyProgressByAmbassador.size} records`
      );
    }
  } catch (err) {
    console.warn("[journey] Load failed:", err?.message || err);
  }
}

function saveJourneyToDisk() {
  try {
    ensureDataDir();
    const obj = {};
    for (const [
      ambassadorId,
      progress,
    ] of journeyProgressByAmbassador.entries()) {
      obj[ambassadorId] = progress;
    }
    fs.writeFileSync(JOURNEY_FILE, JSON.stringify(obj, null, 2), "utf8");
  } catch (err) {
    console.warn("[journey] Save failed:", err?.message || err);
  }
}

// ------------------------
// Helpers
// ------------------------
function hashPassword(password, salt) {
  return crypto
    .createHash("sha256")
    .update(`${salt}:${password}`)
    .digest("hex");
}

function generateId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

function generateSessionId() {
  return crypto.randomBytes(16).toString("hex");
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach((part) => {
    const [k, ...rest] = part.trim().split("=");
    if (!k) return;
    out[k] = decodeURIComponent(rest.join("="));
  });
  return out;
}

function setSessionCookie(res, sessionId, maxAgeMs) {
  const attrs = [
    `sid=${encodeURIComponent(sessionId)}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
  ];
  if (maxAgeMs && Number.isFinite(maxAgeMs)) {
    attrs.push(`Max-Age=${Math.floor(maxAgeMs / 1000)}`);
  }
  res.setHeader("Set-Cookie", attrs.join("; "));
  console.log("Cookie set:", attrs.join("; ")); // ✅ Add logging
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    "sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0"
  );
}

// Enhanced session creation using database
async function createSessionEnhanced(res, userId, role, rememberMe) {
  try {
    const sessionId = generateSessionId();
    const now = new Date();
    const defaultTtlMs = 2 * 60 * 60 * 1000; // 2 hours
    const rememberTtlMs = 30 * 24 * 60 * 60 * 1000; // 30 days
    const ttl = rememberMe ? rememberTtlMs : defaultTtlMs;

    const expiresAt = new Date(now.getTime() + ttl);

    await createSessionDB({
      session_id: sessionId,
      user_id: userId,
      role: role,
      expires_at: expiresAt.toISOString(),
    });

    setSessionCookie(res, sessionId, ttl);

    console.log("Session created:", {
      sessionId,
      userId,
      role,
      expiresAt: expiresAt.toISOString(),
    }); // ✅ Add logging

    return sessionId; // ✅ Return the session ID
  } catch (error) {
    console.error("Session creation error:", error);
    throw error;
  }
}

// Get session from database
async function getSession(req) {
  try {
    const cookies = parseCookies(req);
    const sid = cookies.sid;
    if (!sid) return null;

    const sess = await getSessionDB(sid);
    if (!sess) return null;

    const expiresAt = new Date(sess.expires_at);
    if (Date.now() > expiresAt.getTime()) {
      await deleteSessionDB(sid);
      return null;
    }

    return {
      sid,
      userId: sess.user_id,
      role: sess.role,
      expiresAt: expiresAt.getTime(),
    };
  } catch (error) {
    console.error("Get session error:", error);
    return null;
  }
}

// Legacy session functions (for partners and admins until converted)
function createSession(res, userId, role, rememberMe) {
  const sid = generateSessionId();
  const now = Date.now();
  const defaultTtlMs = 2 * 60 * 60 * 1000;
  const rememberTtlMs = 30 * 24 * 60 * 60 * 1000;
  const ttl = rememberMe ? rememberTtlMs : defaultTtlMs;
  sessions.set(sid, { userId, role, expiresAt: now + ttl });
  setSessionCookie(res, sid, ttl);
  return sid;
}

// ------------------------
// Auth & Role Middleware
// ------------------------
async function requireAuth(req, res, next) {
  const sess = await getSession(req);
  if (!sess) {
    // If it's an HTML page request, redirect to login
    // Otherwise return JSON error for API requests
    if (req.path.endsWith(".html") || req.accepts("text/html")) {
      // Determine redirect URL based on path
      if (req.path.includes("admin")) {
        return res.redirect("/admin-signin.html");
      } else if (req.path.includes("partner")) {
        return res.redirect("/partner-signin");
      } else {
        return res.redirect("/signin");
      }
    }
    return res.status(401).json({ error: "Unauthorized" });
  }
  req.auth = sess;
  next();
}

function requireRole(role) {
  return function (req, res, next) {
    if (!req.auth || req.auth.role !== role) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}

function parseIntParam(value, fallback) {
  const n = Number.parseInt(String(value), 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function listItemsFromMap(
  map,
  { filterFn = () => true, limit = 20, offset = 0 }
) {
  const all = [...map.values()].filter(filterFn);
  const total = all.length;
  const items = all.slice(offset, offset + limit);
  return { total, items, limit, offset };
}

// ------------------------
// Seed test credentials
// ------------------------
const TEST_AMBASSADOR = {
  id: generateId("amb"),
  role: "ambassador",
  email: "ambassador@test.com",
  access_code: "T4LA-1234",
  status: "active",
  salt: crypto.randomBytes(8).toString("hex"),
};
TEST_AMBASSADOR.passwordHash = hashPassword(
  "password123",
  TEST_AMBASSADOR.salt
);

const TEST_PARTNER = {
  id: generateId("par"),
  role: "partner",
  email: "partner@test.com",
  access_code: "T4LP-5678",
  status: "approved",
  organizationName: "Test Partners Inc",
  contactName: "Test Partner",
  salt: crypto.randomBytes(8).toString("hex"),
};
TEST_PARTNER.passwordHash = hashPassword("password123", TEST_PARTNER.salt);

ambassadorsByEmail.set(TEST_AMBASSADOR.email.toLowerCase(), TEST_AMBASSADOR);
partnersByEmail.set(TEST_PARTNER.email.toLowerCase(), TEST_PARTNER);

const TEST_ADMIN = {
  id: generateId("adm"),
  role: "admin",
  email: "admin@test.com",
  access_code: "T4LA-ADMIN",
  status: "active",
  salt: crypto.randomBytes(8).toString("hex"),
};
TEST_ADMIN.passwordHash = hashPassword("password123", TEST_ADMIN.salt);
adminsByEmail.set(TEST_ADMIN.email.toLowerCase(), TEST_ADMIN);

// Add a second test ambassador to see progress differences
const TEST_AMBASSADOR_2 = {
  id: generateId("amb"),
  role: "ambassador",
  email: "ambassador2@test.com",
  access_code: "T4LA-5678",
  status: "active",
  name: "Sarah Smith",
  salt: crypto.randomBytes(8).toString("hex"),
};
TEST_AMBASSADOR_2.passwordHash = hashPassword(
  "password123",
  TEST_AMBASSADOR_2.salt
);
ambassadorsByEmail.set(
  TEST_AMBASSADOR_2.email.toLowerCase(),
  TEST_AMBASSADOR_2
);

// Pre-populate some journey progress for testing
journeyProgressByAmbassador.set(TEST_AMBASSADOR.id, {
  currentMonth: 3,
  completedTasks: {
    "1-linkedin_course": true,
    "1-submit_profile": true,
    "1-second_course": true,
    "1-connect_10": true,
    "1-post_3x": true,
    "2-implement_audit": true,
    "2-submit_article_1": true,
    "2-engage_15": true,
    "2-third_course": true,
    "3-first_event": true,
    "3-follow_up_3": true,
    "3-transformation_post": true,
  },
  startDate: Date.now() - 60 * 24 * 60 * 60 * 1000, // 60 days ago
  monthStartDates: {
    1: Date.now() - 60 * 24 * 60 * 60 * 1000,
    2: Date.now() - 40 * 24 * 60 * 60 * 1000,
    3: Date.now() - 20 * 24 * 60 * 60 * 1000,
  },
  lastUpdated: Date.now(),
});

journeyProgressByAmbassador.set(TEST_AMBASSADOR_2.id, {
  currentMonth: 1,
  completedTasks: {
    "1-linkedin_course": true,
    "1-submit_profile": true,
    "1-second_course": false,
    "1-connect_10": false,
  },
  startDate: Date.now() - 10 * 24 * 60 * 60 * 1000, // 10 days ago
  monthStartDates: { 1: Date.now() - 10 * 24 * 60 * 60 * 1000 },
  lastUpdated: Date.now(),
});

// ------------------------
// Routes - Public
// ------------------------
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/signin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "signin.html"));
});

app.get("/partner-signin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "partner-signin.html"));
});

app.get("/signup", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "signup.html"));
});

app.get("/partner-signup", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "partner-signup.html"));
});

app.get("/admin-signin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin-signin.html"));
});

// ------------------------
// Registration Endpoints
// ------------------------
app.post("/register/ambassador", async (req, res) => {
  try {
    const { email, access_code, password, name } = req.body || {};
    console.log("Registration attempt:", { email, access_code, name });

    if (!email || !access_code || !password || !name) {
      return res.status(400).json({ error: "All fields required" });
    }

    const emailLower = String(email).toLowerCase().trim();
    const access_codeUpper = String(access_code).toUpperCase().trim();

    // Check if user already exists
    const existingUser = await getUserByEmail(emailLower, "ambassador");
    if (existingUser) {
      return res.status(409).json({ error: "Ambassador already exists" });
    }

    // Generate salt and hash password
    const salt = crypto.randomBytes(8).toString("hex");
    const passwordHash = hashPassword(password, salt);

    // Prepare user data with CORRECT field names for db.js
    const userData = {
      email: emailLower,
      access_code: access_codeUpper,
      first_name: name,
      password_hash: passwordHash, // ✅ Correct field name
      salt: salt,
      status: "active",
    };

    // Create user with 'ambassador' role
    const newUser = await createUser(userData, "ambassador"); // ✅ Pass role!

    console.log("User created successfully:", newUser.ambassador_id);

    // Initialize journey progress
    await upsertJourneyProgress(newUser.ambassador_id, {
      current_month: 1,
      completed_tasks: {},
      start_date: new Date().toISOString(),
      month_start_dates: { 1: new Date().toISOString() },
    });

    return res.redirect("/signin?autoPopulate=true");
  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({
      error: "Registration failed",
      details: error.message,
    });
  }
});

app.post("/register/partner", (req, res) => {
  const { email, access_code, password, organizationName, contactName } =
    req.body || {};
  if (
    !email ||
    !access_code ||
    !password ||
    !organizationName ||
    !contactName
  ) {
    return res.status(400).json({ error: "All fields required" });
  }
  const key = String(email).toLowerCase();
  if (partnersByEmail.has(key)) {
    return res.status(409).json({ error: "Partner already exists" });
  }
  const salt = crypto.randomBytes(8).toString("hex");
  const user = {
    id: generateId("par"),
    role: "partner",
    email: key,
    access_code,
    organizationName,
    contactName,
    status: "approved",
    salt,
    passwordHash: hashPassword(password, salt),
  };
  partnersByEmail.set(key, user);
  return res.redirect("/partner-signin?autoPopulate=true");
});

// ------------------------
// Sign-in Endpoints
// ------------------------
app.post("/signin", async (req, res) => {
  try {
    const { email, access_code, password, rememberMe } = req.body || {};

    console.log("Sign-in attempt:", { email, access_code });

    // Validation
    if (!email || !access_code || !password) {
      return res
        .status(400)
        .json({ error: "Email, access code, and password are required" });
    }

    const emailLower = String(email).toLowerCase().trim();
    const access_codeUpper = String(access_code).toUpperCase().trim();

    // Find user by email
    const user = await getUserByEmail(emailLower, "ambassador");

    if (!user) {
      console.log(`Sign-in failed: User not found - ${emailLower}`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Verify access code
    if (user.access_code !== access_codeUpper) {
      console.log(`Sign-in failed: Invalid access code - ${emailLower}`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Verify password
    const computedHash = hashPassword(password, user.salt);
    if (computedHash !== user.password_hash) {
      console.log(`Sign-in failed: Invalid password - ${emailLower}`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check account status
    if (user.status !== "active") {
      console.log(`Sign-in failed: Account inactive - ${emailLower}`);
      return res
        .status(403)
        .json({ error: "Your account is not active. Please contact support." });
    }

    // Create session
    const sessionId = await createSessionEnhanced(
      res,
      user.ambassador_id,
      "ambassador",
      Boolean(rememberMe)
    );

    console.log(`Ambassador signed in: ${emailLower}, Session: ${sessionId}`);

    // ✅ ONLY send JSON - no redirect chaining
    return res.json({
      success: true,
      message: "Sign in successful",
      redirect: "/ambassador-dashboard.html",
      user: {
        id: user.ambassador_id,
        email: user.email,
        name: user.first_name || "Ambassador",
        role: "ambassador",
      },
    });
  } catch (error) {
    console.error("Ambassador sign-in error:", error);
    return res.status(500).json({ error: "Sign in failed. Please try again." });
  }
});

app.post("/partner-signin", async (req, res) => {
  try {
    const { email, access_code, password, rememberMe } = req.body || {};

    if (!email || !access_code || !password) {
      return res
        .status(400)
        .json({ error: "Email, access code, and password are required" });
    }

    const emailLower = String(email).toLowerCase().trim();
    const access_codeUpper = String(access_code).toUpperCase().trim();

    // Find user by email from database
    const user = await getUserByEmail(emailLower, "partner");

    if (!user) {
      console.log(`Partner sign-in failed: User not found - ${emailLower}`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Verify access code
    if (user.access_code !== access_codeUpper) {
      console.log(
        `Partner sign-in failed: Invalid access code - ${emailLower}`
      );
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Verify password
    const computedHash = hashPassword(password, user.salt);
    if (computedHash !== user.password_hash) {
      console.log(`Partner sign-in failed: Invalid password - ${emailLower}`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check account status
    if (user.status !== "approved") {
      console.log(
        `Partner sign-in failed: Account not approved - ${emailLower}`
      );
      return res.status(403).json({ error: "Account not approved" });
    }

    // Create session using database
    const sessionId = await createSessionEnhanced(
      res,
      user.partner_id,
      "partner",
      Boolean(rememberMe)
    );

    console.log(`Partner signed in: ${emailLower}, Session: ${sessionId}`);

    return res.redirect("/partner-dashboard.html");
  } catch (error) {
    console.error("Partner sign-in error:", error);
    return res.status(500).json({ error: "Sign in failed. Please try again." });
  }
});

app.post("/admin-signin", async (req, res) => {
  try {
    const { email, access_code, password, rememberMe } = req.body || {};

    if (!email || !access_code || !password) {
      return res
        .status(400)
        .json({ error: "Email, access code, and password are required" });
    }

    const emailLower = String(email).toLowerCase().trim();
    const access_codeUpper = String(access_code).toUpperCase().trim();

    // Find user by email from database
    const user = await getUserByEmail(emailLower, "admin");

    if (!user) {
      console.log(`Admin sign-in failed: User not found - ${emailLower}`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Verify access code
    if (user.access_code !== access_codeUpper) {
      console.log(`Admin sign-in failed: Invalid access code - ${emailLower}`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Verify password
    const computedHash = hashPassword(password, user.salt);
    if (computedHash !== user.password_hash) {
      console.log(`Admin sign-in failed: Invalid password - ${emailLower}`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check account status
    if (user.status !== "active") {
      console.log(`Admin sign-in failed: Account inactive - ${emailLower}`);
      return res.status(403).json({ error: "Account inactive" });
    }

    // Create session using database
    const sessionId = await createSessionEnhanced(
      res,
      user.admin_id,
      "admin",
      Boolean(rememberMe)
    );

    console.log(`Admin signed in: ${emailLower}, Session: ${sessionId}`);

    // Always return JSON for fetch requests
    return res.json({ ok: true, role: "admin" });
  } catch (error) {
    console.error("Admin sign-in error:", error);
    return res.status(500).json({ error: "Sign in failed. Please try again." });
  }
});

// ------------------------
// Protected Pages
// ------------------------
app.get(
  "/ambassador-dashboard.html",
  requireAuth,
  requireRole("ambassador"),
  async (req, res) => {
    try {
      // ✅ Get user from database instead of memory
      const user = await getUserById(req.auth.userId, "ambassador");

      if (!user) {
        console.log("User not found in database, redirecting to signin");
        return res.redirect("/signin");
      }

      console.log("User authenticated successfully:", user.email);
      res.sendFile(path.join(__dirname, "public", "ambassador-dashboard.html"));
    } catch (error) {
      console.error("Dashboard auth error:", error);
      return res.redirect("/signin");
    }
  }
);

app.get(
  "/ambassador-review.html",
  requireAuth,
  requireRole("ambassador"),
  async (req, res) => {
    try {
      const user = await getUserById(req.auth.userId, "ambassador");
      if (!user) {
        return res.redirect("/signin");
      }
      res.sendFile(path.join(__dirname, "public", "ambassador-review.html"));
    } catch (error) {
      console.error("Ambassador review auth error:", error);
      return res.redirect("/signin");
    }
  }
);

app.get(
  "/partner-dashboard.html",
  requireAuth,
  requireRole("partner"),
  async (req, res) => {
    try {
      const user = await getUserById(req.auth.userId, "partner");
      if (!user) {
        console.log("Partner not found in database, redirecting to signin");
        return res.redirect("/partner-signin");
      }
      console.log("Partner authenticated successfully:", user.email);
      res.sendFile(path.join(__dirname, "public", "partner-dashboard.html"));
    } catch (error) {
      console.error("Partner dashboard auth error:", error);
      return res.redirect("/partner-signin");
    }
  }
);

app.get(
  "/admin-dashboard.html",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const user = await getUserById(req.auth.userId, "admin");
      if (!user) {
        console.log("Admin not found in database, redirecting to signin");
        return res.redirect("/admin-signin.html");
      }
      console.log("Admin authenticated successfully:", user.email);
      res.sendFile(path.join(__dirname, "public", "admin-dashboard.html"));
    } catch (error) {
      console.error("Admin dashboard auth error:", error);
      return res.redirect("/admin-signin.html");
    }
  }
);

app.get("/profile.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "profile.html"));
});

app.get(
  "/article-amb.html",
  requireAuth,
  requireRole("ambassador"),
  (req, res) => {
    res.sendFile(path.join(__dirname, "public", "article-amb.html"));
  }
);

app.get(
  "/article-progress.html",
  requireAuth,
  requireRole("ambassador"),
  (req, res) => {
    res.sendFile(path.join(__dirname, "public", "article-progress.html"));
  }
);

app.get("/Partner-Calls.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "Partner-Calls.html"));
});

app.get("/journey.html", requireAuth, requireRole("ambassador"), (req, res) => {
  res.sendFile(path.join(__dirname, "public", "journey.html"));
});

app.get("/chat-pillar.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "chat-pillar.html"));
});

app.get("/chat-region.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "chat-region.html"));
});

app.get("/creat-Post.html", requireAuth, requireRole("partner"), (req, res) => {
  res.sendFile(path.join(__dirname, "public", "creat-Post.html"));
});

app.get("/CommunityPartView.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "CommunityPartView.html"));
});

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const { role, userId } = req.auth;

    // ✅ Get user from database instead of memory
    const user = await getUserById(userId, role);

    if (!user) {
      console.log(`User not found: ${userId} (${role})`);
      return res.status(404).json({ error: "Not found" });
    }

    // Format response based on role
    const response = {
      id: user.id,
      email: user.email,
      role: user.role,
      status: user.status,
    };

    // Add name field based on role
    if (role === "ambassador") {
      response.name = user.first_name || user.name || "Ambassador";
    } else if (role === "partner") {
      response.name = user.contact_name || user.organization_name || "Partner";
    } else if (role === "admin") {
      response.name = user.first_name || user.name || "Admin";
    } else {
      response.name = "User";
    }

    return res.json(response);
  } catch (error) {
    console.error("Error in /api/me:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ------------------------
// Profile API Endpoints
// ------------------------
app.get("/api/profile", requireAuth, async (req, res) => {
  try {
    const { role, userId } = req.auth;
    const user = await getUserById(userId, role);

    if (!user) {
      return res.status(404).json({ error: "Not found" });
    }

    const profileData = {
      id: user.id,
      email: user.email,
      role: user.role,
      status: user.status,
      access_code: user.access_code,
    };

    if (role === "ambassador") {
      profileData.name = user.first_name || user.name || "";
      profileData.cvFilename = user.cv_filename || null;
    } else if (role === "partner") {
      profileData.organizationName = user.organization_name || "";
      profileData.contactName = user.contact_name || "";
    } else if (role === "admin") {
      profileData.name = user.first_name || user.name || "";
    }

    return res.json(profileData);
  } catch (error) {
    console.error("Error fetching profile:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.patch("/api/profile", requireAuth, async (req, res) => {
  try {
    const { role, userId } = req.auth;
    const { name, contactName, organizationName } = req.body || {};

    const user = await getUserById(userId, role);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const updates = {};

    if (role === "ambassador" || role === "admin") {
      if (typeof name === "string" && name.trim()) {
        updates.first_name = name.trim();
      }
    } else if (role === "partner") {
      if (typeof contactName === "string" && contactName.trim()) {
        updates.contact_name = contactName.trim();
      }
      if (typeof organizationName === "string" && organizationName.trim()) {
        updates.organization_name = organizationName.trim();
      }
    }

    const updatedUser = await updateUser(userId, updates, role);

    return res.json({
      ok: true,
      user: {
        id: updatedUser.id,
        email: updatedUser.email,
        role: updatedUser.role,
        status: updatedUser.status,
        name: updatedUser.first_name || updatedUser.contact_name || "",
        organizationName: updatedUser.organization_name || "",
        contactName: updatedUser.contact_name || "",
      },
    });
  } catch (error) {
    console.error("Error updating profile:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/profile/password", requireAuth, async (req, res) => {
  try {
    const { role, userId } = req.auth;
    const { currentPassword, newPassword } = req.body || {};

    if (!currentPassword || !newPassword) {
      return res
        .status(400)
        .json({ error: "Current password and new password are required" });
    }

    if (newPassword.length < 6) {
      return res
        .status(400)
        .json({ error: "New password must be at least 6 characters" });
    }

    const user = await getUserById(userId, role);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const currentHash = hashPassword(currentPassword, user.salt);
    if (currentHash !== user.password_hash) {
      return res.status(400).json({ error: "Current password is incorrect" });
    }

    // Generate new salt and hash for new password
    const newSalt = crypto.randomBytes(8).toString("hex");
    const newPasswordHash = hashPassword(newPassword, newSalt);

    await updateUser(
      userId,
      {
        password_hash: newPasswordHash,
        salt: newSalt,
      },
      role
    );

    return res.json({ ok: true, message: "Password updated successfully" });
  } catch (error) {
    console.error("Error updating password:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ------------------------
// Journey API Endpoints - ENHANCED WITH REAL-TIME TRACKING
// ------------------------
app.get(
  "/api/journey",
  requireAuth,
  requireRole("ambassador"),
  async (req, res) => {
    try {
      const userId = req.auth.userId;
      const progress = (await getJourneyProgress(userId)) || {
        current_month: 1,
        completed_tasks: {},
        start_date: new Date().toISOString(),
        month_start_dates: { 1: new Date().toISOString() },
      };

      // Calculate statistics
      const totalTasks = JOURNEY_MONTHS.reduce(
        (sum, month) => sum + month.tasks.length,
        0
      );
      const completedCount = Object.keys(progress.completed_tasks || {}).filter(
        (key) => progress.completed_tasks[key]
      ).length;
      const overallProgress =
        totalTasks > 0 ? Math.round((completedCount / totalTasks) * 100) : 0;

      // Get current month data
      const currentMonthData = JOURNEY_MONTHS.find(
        (m) => m.month === progress.current_month
      );
      let currentMonthProgress = 0;
      let currentMonthTasks = [];

      if (currentMonthData) {
        currentMonthTasks = currentMonthData.tasks.map((task) => ({
          id: task.id,
          text: task.text,
          description: task.description || "",
          completed:
            !!progress.completed_tasks[`${progress.current_month}-${task.id}`],
          critical: task.critical || false,
          time: task.time || "",
          deadline: task.deadline || "",
        }));

        const currentMonthCompleted = currentMonthTasks.filter(
          (task) => task.completed
        ).length;
        currentMonthProgress =
          currentMonthTasks.length > 0
            ? Math.round(
                (currentMonthCompleted / currentMonthTasks.length) * 100
              )
            : 0;
      }

      // Get all months with progress
      const months = JOURNEY_MONTHS.map((month) => {
        const monthCompleted = month.tasks.filter(
          (task) => progress.completed_tasks[`${month.month}-${task.id}`]
        ).length;
        const monthProgress =
          month.tasks.length > 0
            ? Math.round((monthCompleted / month.tasks.length) * 100)
            : 0;

        return {
          month: month.month,
          title: month.title,
          milestone: month.milestone,
          totalTasks: month.tasks.length,
          completedTasks: monthCompleted,
          progress: monthProgress,
          isCurrentMonth: month.month === progress.current_month,
          isCompleted: month.month < progress.current_month,
          tasks: month.tasks.map((task) => ({
            id: task.id,
            text: task.text,
            completed: !!progress.completed_tasks[`${month.month}-${task.id}`],
            critical: task.critical || false,
            time: task.time || "",
            deadline: task.deadline || "",
          })),
        };
      });

      return res.json({
        currentMonth: progress.current_month,
        currentMonthTitle: currentMonthData
          ? currentMonthData.title
          : "Month 1",
        currentMonthMilestone: currentMonthData
          ? currentMonthData.milestone
          : "",
        completedTasks: progress.completed_tasks,
        startDate: progress.start_date,
        monthStartDates: progress.month_start_dates || {},
        statistics: {
          totalTasks,
          completedCount,
          overallProgress,
          currentMonthProgress,
          daysInProgram: Math.floor(
            (Date.now() - new Date(progress.start_date).getTime()) /
              (1000 * 60 * 60 * 24)
          ),
        },
        currentMonthTasks,
        months,
      });
    } catch (error) {
      console.error("Journey fetch error:", error);
      return res
        .status(500)
        .json({ error: "Failed to fetch journey progress" });
    }
  }
);

// ENHANCED: Task update endpoint with real-time statistics
app.post(
  "/api/journey/task",
  requireAuth,
  requireRole("ambassador"),
  async (req, res) => {
    try {
      const { taskId, month, completed } = req.body;
      const userId = req.auth.userId;

      if (!taskId || month === undefined) {
        return res.status(400).json({ error: "taskId and month are required" });
      }

      let progress = await getJourneyProgress(userId);
      if (!progress) {
        progress = {
          current_month: 1,
          completed_tasks: {},
          start_date: new Date().toISOString(),
          month_start_dates: { 1: new Date().toISOString() },
        };
      }

      const taskKey = `${month}-${taskId}`;

      if (month > progress.current_month) {
        return res
          .status(400)
          .json({ error: "Complete previous months first" });
      }

      // Update task status
      const completedTasks = progress.completed_tasks || {};
      if (completed) {
        completedTasks[taskKey] = true;
      } else {
        delete completedTasks[taskKey];
      }

      await upsertJourneyProgress(userId, {
        ...progress,
        completed_tasks: completedTasks,
      });

      // Calculate real-time statistics
      const totalTasks = JOURNEY_MONTHS.reduce(
        (sum, m) => sum + m.tasks.length,
        0
      );
      const completedCount = Object.keys(completedTasks).filter(
        (k) => completedTasks[k]
      ).length;
      const overallProgress =
        totalTasks > 0 ? Math.round((completedCount / totalTasks) * 100) : 0;

      return res.json({
        success: true,
        taskKey,
        completed,
        realTimeStats: {
          overallProgress,
          completedCount,
          totalTasks,
        },
      });
    } catch (error) {
      console.error("Error updating task:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// NEW: Lightweight progress polling endpoint
app.get(
  "/api/journey/progress",
  requireAuth,
  requireRole("ambassador"),
  async (req, res) => {
    try {
      const userId = req.auth.userId;
      const progress = await getJourneyProgress(userId);

      if (!progress) {
        return res.json({
          currentMonth: 1,
          overallProgress: 0,
          completedCount: 0,
          totalTasks: JOURNEY_MONTHS.reduce(
            (sum, m) => sum + m.tasks.length,
            0
          ),
          currentMonthProgress: 0,
          lastUpdated: Date.now(),
        });
      }

      const totalTasks = JOURNEY_MONTHS.reduce(
        (sum, m) => sum + m.tasks.length,
        0
      );
      const completedTasks = progress.completed_tasks || {};
      const completedCount = Object.keys(completedTasks).filter(
        (k) => completedTasks[k]
      ).length;
      const overallProgress =
        totalTasks > 0 ? Math.round((completedCount / totalTasks) * 100) : 0;

      const currentMonthData = JOURNEY_MONTHS.find(
        (m) => m.month === progress.current_month
      );
      let currentMonthProgress = 0;

      if (currentMonthData) {
        const currentMonthCompleted = currentMonthData.tasks.filter(
          (task) => completedTasks[`${progress.current_month}-${task.id}`]
        ).length;
        currentMonthProgress =
          currentMonthData.tasks.length > 0
            ? Math.round(
                (currentMonthCompleted / currentMonthData.tasks.length) * 100
              )
            : 0;
      }

      return res.json({
        currentMonth: progress.current_month,
        overallProgress,
        completedCount,
        totalTasks,
        currentMonthProgress,
        lastUpdated: progress.last_updated
          ? new Date(progress.last_updated).getTime()
          : Date.now(),
      });
    } catch (error) {
      console.error("Error fetching journey progress:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.post(
  "/api/journey/advance",
  requireAuth,
  requireRole("ambassador"),
  async (req, res) => {
    try {
      const userId = req.auth.userId;
      let progress = await getJourneyProgress(userId);

      if (!progress) {
        return res.status(400).json({ error: "No journey progress found" });
      }

      // Check if current month is completed
      const currentMonthData = JOURNEY_MONTHS.find(
        (m) => m.month === progress.current_month
      );
      if (!currentMonthData) {
        return res.status(400).json({ error: "Invalid current month" });
      }

      const completedTasks = progress.completed_tasks || {};
      const allTasksCompleted = currentMonthData.tasks.every(
        (task) => completedTasks[`${progress.current_month}-${task.id}`]
      );

      if (!allTasksCompleted) {
        return res
          .status(400)
          .json({ error: "Complete all tasks in current month first" });
      }

      if (progress.current_month >= 12) {
        return res.status(400).json({ error: "Already at final month" });
      }

      // Advance to next month
      const monthStartDates = progress.month_start_dates || {};
      monthStartDates[progress.current_month + 1] = new Date().toISOString();

      const updatedProgress = {
        ...progress,
        current_month: progress.current_month + 1,
        month_start_dates: monthStartDates,
      };

      await upsertJourneyProgress(userId, updatedProgress);

      return res.json({
        success: true,
        newMonth: updatedProgress.current_month,
        message: `Advanced to Month ${updatedProgress.current_month}`,
      });
    } catch (error) {
      console.error("Error advancing month:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.get(
  "/api/journey/days-remaining",
  requireAuth,
  requireRole("ambassador"),
  async (req, res) => {
    try {
      const userId = req.auth.userId;
      const progress = await getJourneyProgress(userId);

      if (!progress) {
        return res.json({ daysRemaining: 365 });
      }

      const startDate = new Date(progress.start_date);
      const today = new Date();
      const daysElapsed = Math.floor(
        (today - startDate) / (1000 * 60 * 60 * 24)
      );
      const daysRemaining = Math.max(0, 365 - daysElapsed);

      return res.json({ daysRemaining });
    } catch (error) {
      console.error("Error fetching days remaining:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ------------------------
// ADMIN Journey Progress APIs
// ------------------------

// Get journey progress for a specific ambassador
app.get(
  "/admin/api/ambassadors/:id/journey",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const progress = (await getJourneyProgress(req.params.id)) || {
        current_month: 1,
        completed_tasks: {},
        start_date: new Date().toISOString(),
        month_start_dates: { 1: new Date().toISOString() },
        last_updated: new Date().toISOString(),
      };

      // Calculate statistics
      const totalTasks = JOURNEY_MONTHS.reduce(
        (sum, month) => sum + month.tasks.length,
        0
      );
      const completedTasks = progress.completed_tasks || {};
      const completedCount = Object.keys(completedTasks).filter(
        (key) => completedTasks[key]
      ).length;
      const overallProgress =
        totalTasks > 0 ? Math.round((completedCount / totalTasks) * 100) : 0;

      // Get current month info
      const currentMonthData = JOURNEY_MONTHS.find(
        (m) => m.month === progress.current_month
      );
      const currentMonthTasks = currentMonthData
        ? currentMonthData.tasks.length
        : 0;
      const currentMonthCompleted = currentMonthData
        ? currentMonthData.tasks.filter(
            (task) => completedTasks[`${progress.current_month}-${task.id}`]
          ).length
        : 0;
      const currentMonthProgress =
        currentMonthTasks > 0
          ? Math.round((currentMonthCompleted / currentMonthTasks) * 100)
          : 0;

      return res.json({
        ambassadorId: req.params.id,
        currentMonth: progress.current_month,
        completedTasks: completedTasks,
        startDate: progress.start_date,
        lastUpdated: progress.last_updated,
        statistics: {
          totalTasks,
          completedCount,
          overallProgress,
          currentMonthProgress,
          currentMonthTitle: currentMonthData
            ? currentMonthData.title
            : "Unknown",
          currentMonthMilestone: currentMonthData
            ? currentMonthData.milestone
            : "",
        },
        months: JOURNEY_MONTHS.map((month) => {
          const monthCompleted = month.tasks.filter(
            (task) => completedTasks[`${month.month}-${task.id}`]
          ).length;
          const monthProgress =
            month.tasks.length > 0
              ? Math.round((monthCompleted / month.tasks.length) * 100)
              : 0;

          return {
            month: month.month,
            title: month.title,
            milestone: month.milestone,
            totalTasks: month.tasks.length,
            completedTasks: monthCompleted,
            progress: monthProgress,
            isCurrentMonth: month.month === progress.current_month,
            isCompleted: month.month < progress.current_month,
            tasks: month.tasks.map((task) => ({
              id: task.id,
              text: task.text,
              completed: !!completedTasks[`${month.month}-${task.id}`],
              critical: task.critical || false,
              time: task.time || "",
              deadline: task.deadline || "",
            })),
          };
        }),
      });
    } catch (error) {
      console.error("Error fetching ambassador journey:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// Get journey progress summary for all ambassadors
app.get(
  "/admin/api/journey/summary",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { items: ambassadors } = await listUsers("ambassador", {});
      const allProgress = await getAllJourneyProgress();

      const summary = await Promise.all(
        ambassadors.map(async (ambassador) => {
          const progress = allProgress.find(
            (p) => p.ambassador_id === ambassador.id
          ) || {
            current_month: 1,
            completed_tasks: {},
            start_date: new Date().toISOString(),
            last_updated: new Date().toISOString(),
          };

          const totalTasks = JOURNEY_MONTHS.reduce(
            (sum, month) => sum + month.tasks.length,
            0
          );
          const completedTasks = progress.completed_tasks || {};
          const completedCount = Object.keys(completedTasks).filter(
            (key) => completedTasks[key]
          ).length;
          const overallProgress =
            totalTasks > 0
              ? Math.round((completedCount / totalTasks) * 100)
              : 0;

          return {
            ambassadorId: ambassador.id,
            ambassadorName: ambassador.first_name || ambassador.email,
            ambassadorEmail: ambassador.email,
            currentMonth: progress.current_month,
            overallProgress,
            completedTasks: completedCount,
            totalTasks,
            startDate: progress.start_date,
            lastUpdated: progress.last_updated
              ? new Date(progress.last_updated).getTime()
              : Date.now(),
            status: ambassador.status,
          };
        })
      );

      // Sort by last updated (most recent first)
      summary.sort((a, b) => (b.lastUpdated || 0) - (a.lastUpdated || 0));

      return res.json({
        total: summary.length,
        ambassadors: summary,
      });
    } catch (error) {
      console.error("Error fetching journey summary:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ------------------------
// Admin Dashboard APIs
// ------------------------
app.get(
  "/admin/api/ambassadors",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;
      const statusFilter = req.query.status;
      const search = req.query.search;

      const filters = {
        status:
          statusFilter && statusFilter !== "all" ? statusFilter : undefined,
        search: search,
        limit,
        offset: (page - 1) * limit,
      };

      const { items, total } = await listUsers("ambassador", filters);

      // Format response
      const formatted = items.map((amb) => ({
        id: amb.id,
        name: amb.first_name || amb.name,
        email: amb.email,
        access_code: amb.access_code,
        status: amb.status,
        joinDate: amb.created_at,
        lastLogin: amb.last_login,
        profileCompleted: amb.cv_filename ? true : false,
      }));

      return res.json({
        ambassadors: formatted,
        total,
        page,
        totalPages: Math.ceil(total / limit),
      });
    } catch (error) {
      console.error("Error fetching ambassadors:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.get(
  "/admin/api/ambassadors/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const ambassador = await getUserById(req.params.id, "ambassador");
      if (!ambassador) {
        return res.status(404).json({ error: "Ambassador not found" });
      }

      return res.json({
        id: ambassador.id,
        name: ambassador.first_name || ambassador.name,
        email: ambassador.email,
        access_code: ambassador.access_code,
        status: ambassador.status,
        joinDate: ambassador.created_at,
        lastLogin: ambassador.last_login,
        profile: {
          completed: ambassador.cv_filename ? true : false,
          data: {},
        },
      });
    } catch (error) {
      console.error("Error fetching ambassador:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.post(
  "/admin/api/ambassadors",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { name, email, access_code } = req.body;

      if (!name || !email || !access_code) {
        return res
          .status(400)
          .json({ error: "Name, email, and access code are required" });
      }

      // Check if email already exists
      const existingUser = await getUserByEmail(
        email.toLowerCase(),
        "ambassador"
      );
      if (existingUser) {
        return res.status(400).json({ error: "Email already registered" });
      }

      const salt = crypto.randomBytes(8).toString("hex");
      const hashedPassword = hashPassword("welcome123", salt);

      const userData = {
        first_name: name,
        email: email.toLowerCase(),
        access_code: access_code.toUpperCase(),
        password_hash: hashedPassword,
        salt,
        status: "active",
      };

      const newAmbassador = await createUser(userData, "ambassador");

      // Initialize journey progress
      await upsertJourneyProgress(newAmbassador.id, {
        current_month: 1,
        completed_tasks: {},
        start_date: new Date().toISOString(),
        month_start_dates: { 1: new Date().toISOString() },
      });

      return res.json({
        success: true,
        ambassador: {
          id: newAmbassador.id,
          name: newAmbassador.first_name,
          email: newAmbassador.email,
          access_code: newAmbassador.access_code,
          status: newAmbassador.status,
        },
      });
    } catch (error) {
      console.error("Error creating ambassador:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.put(
  "/admin/api/ambassadors/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { name, email, access_code, status } = req.body;
      const ambassador = await getUserById(req.params.id, "ambassador");

      if (!ambassador) {
        return res.status(404).json({ error: "Ambassador not found" });
      }

      const updates = {};

      // Check if email is being changed and if it's already taken
      if (email && email.toLowerCase() !== ambassador.email.toLowerCase()) {
        const existingUser = await getUserByEmail(
          email.toLowerCase(),
          "ambassador"
        );
        if (existingUser && existingUser.id !== req.params.id) {
          return res.status(400).json({ error: "Email already registered" });
        }
        updates.email = email.toLowerCase();
      }

      // Check if access code is being changed and if it's already taken
      if (access_code && access_code !== ambassador.access_code) {
        // Note: This would require a query to check for duplicate access codes
        // For now, we'll just update it
        updates.access_code = access_code.toUpperCase();
      }

      if (name) updates.first_name = name;
      if (status) updates.status = status;

      const updatedAmbassador = await updateUser(
        req.params.id,
        updates,
        "ambassador"
      );

      return res.json({
        success: true,
        ambassador: {
          id: updatedAmbassador.id,
          name: updatedAmbassador.first_name,
          email: updatedAmbassador.email,
          access_code: updatedAmbassador.access_code,
          status: updatedAmbassador.status,
        },
      });
    } catch (error) {
      console.error("Error updating ambassador:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.delete(
  "/admin/api/ambassadors/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const ambassador = await getUserById(req.params.id, "ambassador");
      if (!ambassador) {
        return res.status(404).json({ error: "Ambassador not found" });
      }

      // Delete journey progress (if there's a delete function)
      // Note: Journey progress might be automatically deleted via foreign key constraints

      await deleteUser(req.params.id, "ambassador");

      return res.json({ success: true });
    } catch (error) {
      console.error("Error deleting ambassador:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ------------------------
// Partners APIs
// ------------------------
app.get(
  "/admin/api/partners",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { items: partners } = await listUsers("partner", {});
      return res.json({ partners });
    } catch (error) {
      console.error("Error fetching partners:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.post(
  "/admin/api/partners",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { name, email, company, access_code } = req.body;

      if (!name || !email || !access_code) {
        return res
          .status(400)
          .json({ error: "Name, email, and access code are required" });
      }

      // Check if email already exists
      const existingUser = await getUserByEmail(email.toLowerCase(), "partner");
      if (existingUser) {
        return res.status(400).json({ error: "Email already registered" });
      }

      const salt = crypto.randomBytes(8).toString("hex");
      const hashedPassword = hashPassword("welcome123", salt);

      const userData = {
        contact_name: name,
        organization_name: company || "",
        email: email.toLowerCase(),
        access_code: access_code.toUpperCase(),
        password_hash: hashedPassword,
        salt,
        status: "approved",
      };

      const newPartner = await createUser(userData, "partner");

      return res.json({
        success: true,
        partner: {
          id: newPartner.id,
          name: newPartner.contact_name,
          email: newPartner.email,
          company: newPartner.organization_name,
          access_code: newPartner.access_code,
          status: newPartner.status,
        },
      });
    } catch (error) {
      console.error("Error creating partner:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ------------------------
// Articles APIs
// ------------------------
app.get(
  "/admin/api/articles",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const statusFilter = req.query.status;
      const articles = await getArticles(
        statusFilter && statusFilter !== "all" ? { status: statusFilter } : {}
      );
      return res.json({ articles });
    } catch (error) {
      console.error("Error fetching articles:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.post(
  "/admin/api/articles",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { title, excerpt, content, category } = req.body;

      if (!title || !content) {
        return res
          .status(400)
          .json({ error: "Title and content are required" });
      }

      const articleData = {
        title,
        excerpt: excerpt || title.substring(0, 100) + "...",
        content,
        category: category || "general",
        status: "draft",
        ambassador_id: req.auth.userId, // Use ambassador_id to match database schema
        views: 0,
        likes: 0,
      };

      const newArticle = await createArticle(articleData);

      return res.json({ success: true, article: newArticle });
    } catch (error) {
      console.error("Error creating article:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.put(
  "/admin/api/articles/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { title, excerpt, content, category, status } = req.body;
      const articleId = req.params.id;

      // Check if article exists
      const existingArticle = await getArticleById(articleId);
      if (!existingArticle) {
        return res.status(404).json({ error: "Article not found" });
      }

      const updates = {};
      if (title) updates.title = title;
      if (excerpt) updates.excerpt = excerpt;
      if (content) updates.content = content;
      if (category) updates.category = category;
      if (status) updates.status = status;

      const updatedArticle = await updateArticle(articleId, updates);

      return res.json({ success: true, article: updatedArticle });
    } catch (error) {
      console.error("Error updating article:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.delete(
  "/admin/api/articles/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const articleId = req.params.id;

      // Check if article exists
      const article = await getArticleById(articleId);
      if (!article) {
        return res.status(404).json({ error: "Article not found" });
      }

      await deleteArticle(articleId);

      return res.json({ success: true });
    } catch (error) {
      console.error("Error deleting article:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ------------------------
// Ambassador Articles
// ------------------------
app.get(
  "/api/articles",
  requireAuth,
  requireRole("ambassador"),
  async (req, res) => {
    try {
      const articles = await getArticles({ status: "published" });
      return res.json({ articles });
    } catch (error) {
      console.error("Error fetching published articles:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.get(
  "/api/articles/:id",
  requireAuth,
  requireRole("ambassador"),
  async (req, res) => {
    try {
      const article = await getArticleById(req.params.id);
      if (!article || article.status !== "published") {
        return res.status(404).json({ error: "Article not found" });
      }

      // Increment views
      await incrementArticleViews(req.params.id);

      // Fetch updated article with new view count
      const updatedArticle = await getArticleById(req.params.id);

      return res.json({ article: updatedArticle });
    } catch (error) {
      console.error("Error fetching article:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ------------------------
// Ambassador Article Submission APIs
// ------------------------
app.post(
  "/api/ambassador/articles",
  requireAuth,
  requireRole("ambassador"),
  async (req, res) => {
    try {
      const { title, contentHtml, byline } = req.body;

      console.log("Article submission request:", {
        title: title?.substring(0, 50),
        contentLength: contentHtml?.length,
        byline: byline?.substring(0, 50),
        userId: req.auth.userId,
      });

      if (!title || !contentHtml) {
        return res
          .status(400)
          .json({ error: "Title and content are required" });
      }

      // Verify user exists in database
      const user = await getUserById(req.auth.userId, "ambassador");
      if (!user) {
        console.error("User not found:", req.auth.userId);
        return res.status(404).json({ error: "User not found" });
      }

      console.log("User verified:", {
        id: user.ambassador_id || user.id,
        email: user.email
      });

      const articleData = {
        title: String(title).trim(),
        content: String(contentHtml).trim(),
        excerpt: byline
          ? String(byline).trim()
          : String(title).trim().substring(0, 100) + "...",
        category: "general",
        status: "pending",
        ambassador_id: user.ambassador_id || user.id, // ✅ Use correct ID
      };

      // Validate required fields
      if (!articleData.title || articleData.title.length === 0) {
        return res.status(400).json({ error: "Title cannot be empty" });
      }
      if (!articleData.content || articleData.content.length === 0) {
        return res.status(400).json({ error: "Content cannot be empty" });
      }

      console.log("Creating article with data:", {
        title: articleData.title.substring(0, 50),
        ambassador_id: articleData.ambassador_id,
        status: articleData.status,
        contentLength: articleData.content.length,
      });

      const newArticle = await createArticle(articleData);

      console.log("Article created successfully:", newArticle?.article_id);

      return res.json({
        success: true,
        id: newArticle.article_id,
        article: newArticle,
        status: newArticle.status,
      });
    } catch (error) {
      console.error("Error creating article:", error);
      console.error("Error details:", {
        message: error.message,
        code: error.code,
        details: error.details,
        hint: error.hint,
      });
      return res.status(500).json({
        error: "Internal server error",
        message: error.message || "Failed to create article",
      });
    }
  }
);

app.patch(
  "/api/ambassador/articles/:id",
  requireAuth,
  requireRole("ambassador"),
  async (req, res) => {
    try {
      const articleId = req.params.id;
      const { title, contentHtml, byline, status } = req.body;

      // Check if article exists and belongs to the user
      const existingArticle = await getArticleById(articleId);
      if (!existingArticle) {
        return res.status(404).json({ error: "Article not found" });
      }

      // Verify the article belongs to the current user
      if (existingArticle.ambassador_id !== req.auth.userId) {
        return res
          .status(403)
          .json({ error: "You can only edit your own articles" });
      }

      const updates = {};
      if (title) updates.title = title;
      if (contentHtml) updates.content = contentHtml;
      if (byline) updates.excerpt = byline;
      // Allow status update to reset to pending when editing
      if (status) updates.status = status;

      const updatedArticle = await updateArticle(articleId, updates);

      return res.json({
        success: true,
        id: updatedArticle.article_id,
        article: updatedArticle,
        status: updatedArticle.status,
      });
    } catch (error) {
      console.error("Error updating article:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ------------------------
// Posts APIs
// ------------------------
app.get("/api/posts", requireAuth, async (req, res) => {
  try {
    const posts = await getPosts();
    return res.json({ posts });
  } catch (error) {
    console.error("Error fetching posts:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post(
  "/api/posts",
  requireAuth,
  requireRole("partner"),
  async (req, res) => {
    try {
      const { title, content, category } = req.body;

      if (!title || !content) {
        return res
          .status(400)
          .json({ error: "Title and content are required" });
      }

      const postData = {
        title,
        content,
        category: category || "general",
        author_id: req.auth.userId,
        author_name: "Partner",
      };

      const newPost = await createPost(postData);

      return res.json({ success: true, post: newPost });
    } catch (error) {
      console.error("Error creating post:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ------------------------
// CV Upload
// ------------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, CVS_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, "cv-" + uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /pdf|doc|docx/;
    const extname = allowedTypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = allowedTypes.test(file.mimetype);

    if (extname && mimetype) {
      cb(null, true);
    } else {
      cb(new Error("Only PDF, DOC, and DOCX files are allowed"));
    }
  },
});

app.post(
  "/api/upload-cv",
  requireAuth,
  requireRole("ambassador"),
  upload.single("cv"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
      }

      const user = await getUserById(req.auth.userId, "ambassador");
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Remove old CV if exists
      if (user.cv_filename) {
        const oldPath = path.join(CVS_DIR, user.cv_filename);
        if (fs.existsSync(oldPath)) {
          fs.unlinkSync(oldPath);
        }
      }

      // Update user in database
      await updateUser(
        req.auth.userId,
        { cv_filename: req.file.filename },
        "ambassador"
      );

      return res.json({
        success: true,
        filename: req.file.filename,
        message: "CV uploaded successfully",
      });
    } catch (error) {
      console.error("Error uploading CV:", error);
      return res.status(500).json({ error: "Failed to upload CV" });
    }
  }
);

// ------------------------
// Notifications
// ------------------------
app.get("/api/notifications", requireAuth, (req, res) => {
  const userId = req.auth.userId;
  const notifications = notificationsByUserId.get(userId) || [];

  // Mark all as read
  notifications.forEach((n) => (n.read = true));

  return res.json({ notifications });
});

app.post("/api/notifications/clear", requireAuth, (req, res) => {
  const userId = req.auth.userId;
  notificationsByUserId.set(userId, []);
  return res.json({ success: true });
});

// ------------------------
// Dashboard Stats
// ------------------------
app.get("/api/dashboard/stats", requireAuth, async (req, res) => {
  try {
    const { role, userId } = req.auth;

    if (role === "ambassador") {
      const user = await getUserById(userId, "ambassador");
      if (!user) return res.status(404).json({ error: "User not found" });

      const progress = (await getJourneyProgress(userId)) || {
        current_month: 1,
        completed_tasks: {},
        start_date: new Date().toISOString(),
      };

      // Calculate journey stats
      const totalTasks = JOURNEY_MONTHS.reduce(
        (sum, month) => sum + month.tasks.length,
        0
      );
      const completedTasks = progress.completed_tasks || {};
      const completedCount = Object.keys(completedTasks).filter(
        (key) => completedTasks[key]
      ).length;
      const overallProgress =
        totalTasks > 0 ? Math.round((completedCount / totalTasks) * 100) : 0;

      // Days since joining
      const joinDate = user.created_at ? new Date(user.created_at) : new Date();
      const today = new Date();
      const daysInProgram = Math.floor(
        (today - joinDate) / (1000 * 60 * 60 * 24)
      );

      // Get recent published articles
      const articles = await getArticles({ status: "published" });
      const recentArticles = articles.slice(0, 3).map((article) => ({
        id: article.article_id,
        title: article.title,
        excerpt: article.excerpt,
        date: article.created_at,
        category: article.category,
      }));

      return res.json({
        stats: {
          overallProgress,
          completedTasks: completedCount,
          totalTasks,
          currentMonth: progress.current_month,
          daysInProgram: Math.max(0, daysInProgram),
          daysRemaining: Math.max(0, 365 - daysInProgram),
        },
        user: {
          name: user.first_name || "Ambassador",
          email: user.email,
          joinDate: user.created_at,
        },
        recentArticles,
      });
    } else if (role === "partner") {
      const user = await getUserById(userId, "partner");
      if (!user) return res.status(404).json({ error: "User not found" });

      const posts = await getPosts({ authorId: userId });

      return res.json({
        stats: {
          postsCreated: posts.length,
          totalEngagement: 0, // Could track likes/comments
          partnerSince: user.created_at || new Date().toISOString(),
        },
        user: {
          organizationName: user.organization_name,
          contactName: user.contact_name,
          email: user.email,
        },
      });
    } else if (role === "admin") {
      const { items: ambassadors } = await listUsers("ambassador", {});
      const { items: partners } = await listUsers("partner", {});
      const articles = await getArticles({});

      return res.json({
        stats: {
          totalAmbassadors: ambassadors.length,
          totalPartners: partners.length,
          totalArticles: articles.length,
          activeAmbassadors: ambassadors.filter((a) => a.status === "active")
            .length,
        },
      });
    }

    return res.json({ stats: {} });
  } catch (error) {
    console.error("Error fetching dashboard stats:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ------------------------
// Logout
// ------------------------
app.post("/api/logout", async (req, res) => {
  const cookies = parseCookies(req);
  const sid = cookies.sid;
  if (sid) {
    // Delete from database
    await deleteSessionDB(sid);
    // Delete from memory
    sessions.delete(sid);
  }
  clearSessionCookie(res);
  return res.redirect("/signin");
});

// ------------------------
// Initialize data
// ------------------------
ensureDataDir();
loadArticlesFromDisk();
loadPostsFromDisk();
loadJourneyFromDisk();

// Auto-save data periodically
setInterval(() => {
  saveJourneyToDisk();
  saveArticlesToDisk();
  savePostsToDisk();
}, 60000); // Every minute

// ------------------------
// Start Server
// ------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(
    `[journey] Journey progress tracking ENABLED with REAL-TIME updates`
  );
  console.log(
    `[journey] Loaded ${journeyProgressByAmbassador.size} ambassador progress records`
  );
  console.log(`[data] Data directory: ${DATA_DIR}`);
});
