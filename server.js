require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const multer = require('multer');
const JOURNEY_MONTHS = require('./journey-db.js');
const app = express();
const { v4: uuidv4 } = require('uuid');

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
  deleteSession: deleteSessionDB 
} = require('./models/db.js');

// ------------------------
// Basic Middleware
// ------------------------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Disable cache in development and simple request logging
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  console.log(`${req.method} ${req.url}`);
  next();
});

// Serve static assets
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

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
const DATA_DIR = path.join(__dirname, 'data');
const ARTICLES_FILE = path.join(DATA_DIR, 'articles.json');
const POSTS_FILE = path.join(DATA_DIR, 'posts.json');
const JOURNEY_FILE = path.join(DATA_DIR, 'journey.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const CVS_DIR = path.join(UPLOADS_DIR, 'cvs');

function ensureDataDir() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (!fs.existsSync(CVS_DIR)) {
      fs.mkdirSync(CVS_DIR, { recursive: true });
    }
  } catch (err) {
    console.warn('[data] Failed to ensure data directory:', err && err.message ? err.message : err);
  }
}

function loadArticlesFromDisk() {
  try {
    ensureDataDir();
    if (!fs.existsSync(ARTICLES_FILE)) return;
    const raw = fs.readFileSync(ARTICLES_FILE, 'utf8');
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      articlesById.clear();
      for (const art of parsed) {
        if (art && art.id) {
          articlesById.set(String(art.id), art);
        }
      }
      console.log(`[articles] Loaded ${articlesById.size} article(s) from disk`);
    }
  } catch (err) {
    console.warn('[articles] Failed to load from disk:', err && err.message ? err.message : err);
  }
}

function saveArticlesToDisk() {
  try {
    ensureDataDir();
    const all = [...articlesById.values()];
    const json = JSON.stringify(all, null, 2);
    fs.writeFileSync(ARTICLES_FILE, json, 'utf8');
  } catch (err) {
    console.warn('[articles] Failed to save to disk:', err && err.message ? err.message : err);
  }
}

function loadPostsFromDisk() {
  try {
    ensureDataDir();
    if (!fs.existsSync(POSTS_FILE)) return;
    const raw = fs.readFileSync(POSTS_FILE, 'utf8');
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
    console.warn('[posts] Failed to load from disk:', err && err.message ? err.message : err);
  }
}

function savePostsToDisk() {
  try {
    ensureDataDir();
    const all = [...postsById.values()];
    const json = JSON.stringify(all, null, 2);
    fs.writeFileSync(POSTS_FILE, json, 'utf8');
    console.log(`[posts] Saved ${all.length} post(s) to disk`);
  } catch (err) {
    console.warn('[posts] Failed to save to disk:', err && err.message ? err.message : err);
  }
}

function loadJourneyFromDisk() {
  try {
    ensureDataDir();
    if (!fs.existsSync(JOURNEY_FILE)) return;
    const raw = fs.readFileSync(JOURNEY_FILE, 'utf8');
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (typeof parsed === 'object') {
      journeyProgressByAmbassador.clear();
      for (const [ambassadorId, progress] of Object.entries(parsed)) {
        journeyProgressByAmbassador.set(ambassadorId, progress);
      }
      console.log(`[journey] Loaded ${journeyProgressByAmbassador.size} records`);
    }
  } catch (err) {
    console.warn('[journey] Load failed:', err?.message || err);
  }
}

function saveJourneyToDisk() {
  try {
    ensureDataDir();
    const obj = {};
    for (const [ambassadorId, progress] of journeyProgressByAmbassador.entries()) {
      obj[ambassadorId] = progress;
    }
    fs.writeFileSync(JOURNEY_FILE, JSON.stringify(obj, null, 2), 'utf8');
  } catch (err) {
    console.warn('[journey] Save failed:', err?.message || err);
  }
}

// ------------------------
// Helpers
// ------------------------
function hashPassword(password, salt) {
  return crypto.createHash('sha256').update(`${salt}:${password}`).digest('hex');
}

function generateId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString('hex')}`;
}

function generateSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(part => {
    const [k, ...rest] = part.trim().split('=');
    if (!k) return;
    out[k] = decodeURIComponent(rest.join('='));
  });
  return out;
}

function setSessionCookie(res, sessionId, maxAgeMs) {
  const attrs = [
    `sid=${encodeURIComponent(sessionId)}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Lax'
  ];
  if (maxAgeMs && Number.isFinite(maxAgeMs)) {
    attrs.push(`Max-Age=${Math.floor(maxAgeMs / 1000)}`);
  }
  res.setHeader('Set-Cookie', attrs.join('; '));
  console.log('Cookie set:', attrs.join('; ')); // ✅ Add logging
}



function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
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
      expires_at: expiresAt.toISOString()
    });
    
    setSessionCookie(res, sessionId, ttl);
    
    console.log('Session created:', { sessionId, userId, role, expiresAt: expiresAt.toISOString() }); // ✅ Add logging
    
    return sessionId; // ✅ Return the session ID
  } catch (error) {
    console.error('Session creation error:', error);
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
      expiresAt: expiresAt.getTime() 
    };
  } catch (error) {
    console.error('Get session error:', error);
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
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.auth = sess;
  next();
}

function requireRole(role) {
  return function(req, res, next) {
    if (!req.auth || req.auth.role !== role) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

function parseIntParam(value, fallback) {
  const n = Number.parseInt(String(value), 10);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function listItemsFromMap(map, { filterFn = () => true, limit = 20, offset = 0 }) {
  const all = [...map.values()].filter(filterFn);
  const total = all.length;
  const items = all.slice(offset, offset + limit);
  return { total, items, limit, offset };
}

// ------------------------
// Seed test credentials
// ------------------------
const TEST_AMBASSADOR = {
  id: generateId('amb'),
  role: 'ambassador',
  email: 'ambassador@test.com',
  access_code: 'T4LA-1234',
  status: 'active',
  salt: crypto.randomBytes(8).toString('hex')
};
TEST_AMBASSADOR.passwordHash = hashPassword('password123', TEST_AMBASSADOR.salt);

const TEST_PARTNER = {
  id: generateId('par'),
  role: 'partner',
  email: 'partner@test.com',
  access_code: 'T4LP-5678',
  status: 'approved',
  organizationName: 'Test Partners Inc',
  contactName: 'Test Partner',
  salt: crypto.randomBytes(8).toString('hex')
};
TEST_PARTNER.passwordHash = hashPassword('password123', TEST_PARTNER.salt);

ambassadorsByEmail.set(TEST_AMBASSADOR.email.toLowerCase(), TEST_AMBASSADOR);
partnersByEmail.set(TEST_PARTNER.email.toLowerCase(), TEST_PARTNER);

const TEST_ADMIN = {
  id: generateId('adm'),
  role: 'admin',
  email: 'admin@test.com',
  access_code: 'T4LA-ADMIN',
  status: 'active',
  salt: crypto.randomBytes(8).toString('hex')
};
TEST_ADMIN.passwordHash = hashPassword('password123', TEST_ADMIN.salt);
adminsByEmail.set(TEST_ADMIN.email.toLowerCase(), TEST_ADMIN);

// Add a second test ambassador to see progress differences
const TEST_AMBASSADOR_2 = {
  id: generateId('amb'),
  role: 'ambassador',
  email: 'ambassador2@test.com',
  access_code: 'T4LA-5678',
  status: 'active',
  name: 'Sarah Smith',
  salt: crypto.randomBytes(8).toString('hex')
};
TEST_AMBASSADOR_2.passwordHash = hashPassword('password123', TEST_AMBASSADOR_2.salt);
ambassadorsByEmail.set(TEST_AMBASSADOR_2.email.toLowerCase(), TEST_AMBASSADOR_2);

// Pre-populate some journey progress for testing
journeyProgressByAmbassador.set(TEST_AMBASSADOR.id, {
  currentMonth: 3,
  completedTasks: {
    '1-linkedin_course': true,
    '1-submit_profile': true,
    '1-second_course': true,
    '1-connect_10': true,
    '1-post_3x': true,
    '2-implement_audit': true,
    '2-submit_article_1': true,
    '2-engage_15': true,
    '2-third_course': true,
    '3-first_event': true,
    '3-follow_up_3': true,
    '3-transformation_post': true
  },
  startDate: Date.now() - (60 * 24 * 60 * 60 * 1000), // 60 days ago
  monthStartDates: { 1: Date.now() - (60 * 24 * 60 * 60 * 1000), 2: Date.now() - (40 * 24 * 60 * 60 * 1000), 3: Date.now() - (20 * 24 * 60 * 60 * 1000) },
  lastUpdated: Date.now()
});

journeyProgressByAmbassador.set(TEST_AMBASSADOR_2.id, {
  currentMonth: 1,
  completedTasks: {
    '1-linkedin_course': true,
    '1-submit_profile': true,
    '1-second_course': false,
    '1-connect_10': false
  },
  startDate: Date.now() - (10 * 24 * 60 * 60 * 1000), // 10 days ago
  monthStartDates: { 1: Date.now() - (10 * 24 * 60 * 60 * 1000) },
  lastUpdated: Date.now()
});

// ------------------------
// Routes - Public
// ------------------------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/signin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signin.html'));
});

app.get('/partner-signin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'partner-signin.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/partner-signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'partner-signup.html'));
});

app.get('/admin-signin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-signin.html'));
});

// ------------------------
// Registration Endpoints
// ------------------------
app.post('/register/ambassador', async (req, res) => {
  try {
    const { email, access_code, password, name } = req.body || {};
    console.log('Registration attempt:', { email, access_code, name });
    
    if (!email || !access_code || !password || !name) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    const emailLower = String(email).toLowerCase().trim();
    const access_codeUpper = String(access_code).toUpperCase().trim();
    
    // Check if user already exists
    const existingUser = await getUserByEmail(emailLower, 'ambassador');
    if (existingUser) {
      return res.status(409).json({ error: 'Ambassador already exists' });
    }
    
    // Generate salt and hash password
    const salt = crypto.randomBytes(8).toString('hex');
    const passwordHash = hashPassword(password, salt);
    
    // Prepare user data with CORRECT field names for db.js
    const userData = {
      email: emailLower,
      access_code: access_codeUpper,
      first_name: name,
      password_hash: passwordHash,  // ✅ Correct field name
      salt: salt,
      status: 'active'
    };
    
    // Create user with 'ambassador' role
    const newUser = await createUser(userData, 'ambassador');  // ✅ Pass role!
    
    console.log('User created successfully:', newUser.ambassador_id);
    
    // Initialize journey progress
    await upsertJourneyProgress(newUser.ambassador_id, {
      current_month: 1,
      completed_tasks: {},
      start_date: new Date().toISOString(),
      month_start_dates: { "1": new Date().toISOString() }
    });
    
    return res.redirect('/signin?autoPopulate=true');
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ 
      error: 'Registration failed', 
      details: error.message 
    });
  }
});

app.post('/register/partner', (req, res) => {
  const { email, access_code, password, organizationName, contactName } = req.body || {};
  if (!email || !access_code || !password || !organizationName || !contactName) {
    return res.status(400).json({ error: 'All fields required' });
  }
  const key = String(email).toLowerCase();
  if (partnersByEmail.has(key)) {
    return res.status(409).json({ error: 'Partner already exists' });
  }
  const salt = crypto.randomBytes(8).toString('hex');
  const user = {
    id: generateId('par'),
    role: 'partner',
    email: key,
    access_code,
    organizationName,
    contactName,
    status: 'approved',
    salt,
    passwordHash: hashPassword(password, salt)
  };
  partnersByEmail.set(key, user);
  return res.redirect('/partner-signin?autoPopulate=true');
});

// ------------------------
// Sign-in Endpoints
// ------------------------
app.post('/signin', async (req, res) => {
  try {
    const { email, access_code, password, rememberMe } = req.body || {};

    console.log('Sign-in attempt:', { email, access_code });
    
    // Validation
    if (!email || !access_code || !password) {
      return res.status(400).json({ error: 'Email, access code, and password are required' });
    }
    
    const emailLower = String(email).toLowerCase().trim();
    const access_codeUpper = String(access_code).toUpperCase().trim();
    
    // Find user by email
    const user = await getUserByEmail(emailLower, 'ambassador');
    
    if (!user) {
      console.log(`Sign-in failed: User not found - ${emailLower}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify access code
    if (user.access_code !== access_codeUpper) {
      console.log(`Sign-in failed: Invalid access code - ${emailLower}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify password
    const computedHash = hashPassword(password, user.salt);
    if (computedHash !== user.password_hash) {
      console.log(`Sign-in failed: Invalid password - ${emailLower}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check account status
    if (user.status !== 'active') {
      console.log(`Sign-in failed: Account inactive - ${emailLower}`);
      return res.status(403).json({ error: 'Your account is not active. Please contact support.' });
    }
    
    // Create session
    const sessionId = await createSessionEnhanced(res, user.ambassador_id, 'ambassador', Boolean(rememberMe));
    
    console.log(`Ambassador signed in: ${emailLower}, Session: ${sessionId}`);
    
    // ✅ ONLY send JSON - no redirect chaining
    return res.json({ 
      success: true,
      message: 'Sign in successful',
      redirect: '/ambassador-dashboard.html',
      user: {
        id: user.ambassador_id,
        email: user.email,
        name: user.first_name || 'Ambassador',
        role: 'ambassador'
      }
    });
    
  } catch (error) {
    console.error('Ambassador sign-in error:', error);
    return res.status(500).json({ error: 'Sign in failed. Please try again.' });
  }
});

app.post('/partner-signin', (req, res) => {
  const { email, access_code, password, rememberMe } = req.body || {};
  const key = (email || '').toLowerCase();
  const user = partnersByEmail.get(key);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.access_code !== access_code) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const computed = hashPassword(String(password || ''), user.salt);
  if (computed !== user.passwordHash) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.status !== 'approved') {
    return res.status(403).json({ error: 'Account not approved' });
  }
  createSession(res, user.id, 'partner', Boolean(rememberMe));
  return res.redirect('/partner-dashboard.html');
});

app.post('/admin-signin', (req, res) => {
  const { email, access_code, password, rememberMe } = req.body || {};
  const key = (email || '').toLowerCase();
  const user = adminsByEmail.get(key);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.access_code !== access_code) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const computed = hashPassword(String(password || ''), user.salt);
  if (computed !== user.passwordHash) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.status !== 'active') {
    return res.status(403).json({ error: 'Account inactive' });
  }
  createSession(res, user.id, 'admin', Boolean(rememberMe));
  // Always return JSON for fetch requests
  return res.json({ ok: true, role: 'admin' });
});

// ------------------------
// Protected Pages
// ------------------------
app.get('/ambassador-dashboard.html', requireAuth, requireRole('ambassador'), async (req, res) => {
  try {
    // ✅ Get user from database instead of memory
    const user = await getUserById(req.auth.userId, 'ambassador');
    
    if (!user) {
      console.log('User not found in database, redirecting to signin');
      return res.redirect('/signin');
    }
    
    console.log('User authenticated successfully:', user.email);
    res.sendFile(path.join(__dirname, 'public', 'ambassador-dashboard.html'));
  } catch (error) {
    console.error('Dashboard auth error:', error);
    return res.redirect('/signin');
  }
});

app.get('/ambassador-review.html', requireAuth, requireRole('ambassador'), (req, res) => {
  const user = [...ambassadorsByEmail.values()].find(u => u.id === req.auth.userId);
  if (!user) {
    return res.redirect('/signin');
  }
  res.sendFile(path.join(__dirname, 'public', 'ambassador-review.html'));
});

app.get('/partner-dashboard.html', requireAuth, requireRole('partner'), (req, res) => {
  const user = [...partnersByEmail.values()].find(u => u.id === req.auth.userId);
  if (!user) {
    return res.redirect('/partner-signin');
  }
  res.sendFile(path.join(__dirname, 'public', 'partner-dashboard.html'));
});

app.get('/admin-dashboard.html', requireAuth, requireRole('admin'), (req, res) => {
  const user = [...adminsByEmail.values()].find(u => u.id === req.auth.userId);
  if (!user) {
    return res.redirect('/admin-signin');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.get('/profile.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/article-amb.html', requireAuth, requireRole('ambassador'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'article-amb.html'));
});

app.get('/article-progress.html', requireAuth, requireRole('ambassador'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'article-progress.html'));
});

app.get('/Partner-Calls.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'Partner-Calls.html'));
});

app.get('/journey.html', requireAuth, requireRole('ambassador'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'journey.html'));
});

app.get('/chat-pillar.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'chat-pillar.html'));
});

app.get('/chat-region.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'chat-region.html'));
});

app.get('/creat-Post.html', requireAuth, requireRole('partner'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'creat-Post.html'));
});

app.get('/CommunityPartView.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'CommunityPartView.html'));
});

app.get('/api/me', requireAuth, (req, res) => {
  const { role, userId } = req.auth;
  let user = null;
  if (role === 'ambassador') {
    user = [...ambassadorsByEmail.values()].find(u => u.id === userId) || null;
  } else if (role === 'partner') {
    user = [...partnersByEmail.values()].find(u => u.id === userId) || null;
  } else if (role === 'admin') {
    user = [...adminsByEmail.values()].find(u => u.id === userId) || null;
  }
  if (!user) return res.status(404).json({ error: 'Not found' });
  
  return res.json({ 
    id: user.id, 
    email: user.email, 
    role: user.role, 
    status: user.status,
    name: user.name || user.contactName || 'User'
  });
});

// ------------------------
// Profile API Endpoints
// ------------------------
app.get('/api/profile', requireAuth, (req, res) => {
  const { role, userId } = req.auth;
  let user = null;
  if (role === 'ambassador') {
    user = [...ambassadorsByEmail.values()].find(u => u.id === userId) || null;
  } else if (role === 'partner') {
    user = [...partnersByEmail.values()].find(u => u.id === userId) || null;
  } else if (role === 'admin') {
    user = [...adminsByEmail.values()].find(u => u.id === userId) || null;
  }
  if (!user) return res.status(404).json({ error: 'Not found' });
  
  const profileData = {
    id: user.id,
    email: user.email,
    role: user.role,
    status: user.status,
    access_code: user.access_code
  };
  
  if (role === 'ambassador') {
    profileData.name = user.name || '';
    profileData.cvFilename = user.cvFilename || null;
  } else if (role === 'partner') {
    profileData.organizationName = user.organizationName || '';
    profileData.contactName = user.contactName || '';
  } else if (role === 'admin') {
    profileData.name = user.name || '';
  }
  
  return res.json(profileData);
});

app.patch('/api/profile', requireAuth, (req, res) => {
  const { role, userId } = req.auth;
  const { name, contactName, organizationName } = req.body || {};
  
  let user = null;
  let userMap = null;
  
  if (role === 'ambassador') {
    user = [...ambassadorsByEmail.values()].find(u => u.id === userId) || null;
    userMap = ambassadorsByEmail;
  } else if (role === 'partner') {
    user = [...partnersByEmail.values()].find(u => u.id === userId) || null;
    userMap = partnersByEmail;
  } else if (role === 'admin') {
    user = [...adminsByEmail.values()].find(u => u.id === userId) || null;
    userMap = adminsByEmail;
  }
  
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  if (role === 'ambassador' || role === 'admin') {
    if (typeof name === 'string' && name.trim()) {
      user.name = name.trim();
    }
  } else if (role === 'partner') {
    if (typeof contactName === 'string' && contactName.trim()) {
      user.contactName = contactName.trim();
    }
    if (typeof organizationName === 'string' && organizationName.trim()) {
      user.organizationName = organizationName.trim();
    }
  }
  
  const emailKey = user.email.toLowerCase();
  userMap.set(emailKey, user);
  
  return res.json({ ok: true, user: {
    id: user.id,
    email: user.email,
    role: user.role,
    status: user.status,
    name: user.name || user.contactName || '',
    organizationName: user.organizationName || '',
    contactName: user.contactName || ''
  }});
});

app.post('/api/profile/password', requireAuth, (req, res) => {
  const { role, userId } = req.auth;
  const { currentPassword, newPassword } = req.body || {};
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required' });
  }
  
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }
  
  let user = null;
  let userMap = null;
  
  if (role === 'ambassador') {
    user = [...ambassadorsByEmail.values()].find(u => u.id === userId) || null;
    userMap = ambassadorsByEmail;
  } else if (role === 'partner') {
    user = [...partnersByEmail.values()].find(u => u.id === userId) || null;
    userMap = partnersByEmail;
  } else if (role === 'admin') {
    user = [...adminsByEmail.values()].find(u => u.id === userId) || null;
    userMap = adminsByEmail;
  }
  
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  const currentHash = hashPassword(currentPassword, user.salt);
  if (currentHash !== user.passwordHash) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  
  user.passwordHash = hashPassword(newPassword, user.salt);
  userMap.set(user.email.toLowerCase(), user);
  
  return res.json({ ok: true, message: 'Password updated successfully' });
});

// ------------------------
// Journey API Endpoints - ENHANCED WITH REAL-TIME TRACKING
// ------------------------
app.get('/api/journey', requireAuth, requireRole('ambassador'), async (req, res) => {
  try {
    const userId = req.auth.userId;
    const progress = await getJourneyProgress(userId) || {
      current_month: 1,
      completed_tasks: {},
      start_date: new Date().toISOString(),
      month_start_dates: { 1: new Date().toISOString() }
    };
    
    // Calculate statistics
    const totalTasks = JOURNEY_MONTHS.reduce((sum, month) => sum + month.tasks.length, 0);
    const completedCount = Object.keys(progress.completed_tasks || {}).filter(key => progress.completed_tasks[key]).length;
    const overallProgress = totalTasks > 0 ? Math.round((completedCount / totalTasks) * 100) : 0;
    
    // Get current month data
    const currentMonthData = JOURNEY_MONTHS.find(m => m.month === progress.current_month);
    let currentMonthProgress = 0;
    let currentMonthTasks = [];
    
    if (currentMonthData) {
      currentMonthTasks = currentMonthData.tasks.map(task => ({
        id: task.id,
        text: task.text,
        description: task.description || '',
        completed: !!progress.completed_tasks[`${progress.current_month}-${task.id}`],
        critical: task.critical || false,
        time: task.time || '',
        deadline: task.deadline || ''
      }));
      
      const currentMonthCompleted = currentMonthTasks.filter(task => task.completed).length;
      currentMonthProgress = currentMonthTasks.length > 0 
        ? Math.round((currentMonthCompleted / currentMonthTasks.length) * 100) 
        : 0;
    }
    
    // Get all months with progress
    const months = JOURNEY_MONTHS.map(month => {
      const monthCompleted = month.tasks.filter(task => 
        progress.completed_tasks[`${month.month}-${task.id}`]
      ).length;
      const monthProgress = month.tasks.length > 0 
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
        tasks: month.tasks.map(task => ({
          id: task.id,
          text: task.text,
          completed: !!progress.completed_tasks[`${month.month}-${task.id}`],
          critical: task.critical || false,
          time: task.time || '',
          deadline: task.deadline || ''
        }))
      };
    });
    
    return res.json({
      currentMonth: progress.current_month,
      currentMonthTitle: currentMonthData ? currentMonthData.title : 'Month 1',
      currentMonthMilestone: currentMonthData ? currentMonthData.milestone : '',
      completedTasks: progress.completed_tasks,
      startDate: progress.start_date,
      monthStartDates: progress.month_start_dates || {},
      statistics: {
        totalTasks,
        completedCount,
        overallProgress,
        currentMonthProgress,
        daysInProgram: Math.floor((Date.now() - new Date(progress.start_date).getTime()) / (1000 * 60 * 60 * 24))
      },
      currentMonthTasks,
      months
    });
  } catch (error) {
    console.error('Journey fetch error:', error);
    return res.status(500).json({ error: 'Failed to fetch journey progress' });
  }
});

// ENHANCED: Task update endpoint with real-time statistics
app.post('/api/journey/task', requireAuth, requireRole('ambassador'), async (req, res) => {
  try {
    const { taskId, month, completed } = req.body;
    const userId = req.auth.userId;
    
    if (!taskId || month === undefined) {
      return res.status(400).json({ error: 'taskId and month are required' });
    }
    
    let progress = await getJourneyProgress(userId);
    if (!progress) {
      progress = {
        current_month: 1,
        completed_tasks: {},
        start_date: new Date().toISOString(),
        month_start_dates: { 1: new Date().toISOString() }
      };
    }
    
    const taskKey = `${month}-${taskId}`;
    
    if (month > progress.current_month) {
      return res.status(400).json({ error: 'Complete previous months first' });
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
      completed_tasks: completedTasks
    });
    
    // Calculate real-time statistics
    const totalTasks = JOURNEY_MONTHS.reduce((sum, m) => sum + m.tasks.length, 0);
    const completedCount = Object.keys(completedTasks).filter(k => completedTasks[k]).length;
    const overallProgress = totalTasks > 0 ? Math.round((completedCount / totalTasks) * 100) : 0;
    
    return res.json({ 
      success: true, 
      taskKey, 
      completed,
      realTimeStats: {
        overallProgress,
        completedCount,
        totalTasks
      }
    });
  } catch (error) {
    console.error('Error updating task:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// NEW: Lightweight progress polling endpoint
app.get('/api/journey/progress', requireAuth, requireRole('ambassador'), (req, res) => {
  const userId = req.auth.userId;
  const progress = journeyProgressByAmbassador.get(userId);
  
  if (!progress) {
    return res.json({
      currentMonth: 1,
      overallProgress: 0,
      completedCount: 0,
      totalTasks: JOURNEY_MONTHS.reduce((sum, m) => sum + m.tasks.length, 0),
      currentMonthProgress: 0,
      lastUpdated: Date.now()
    });
  }
  
  const totalTasks = JOURNEY_MONTHS.reduce((sum, m) => sum + m.tasks.length, 0);
  const completedCount = Object.keys(progress.completedTasks).filter(k => progress.completedTasks[k]).length;
  const overallProgress = totalTasks > 0 ? Math.round((completedCount / totalTasks) * 100) : 0;
  
  const currentMonthData = JOURNEY_MONTHS.find(m => m.month === progress.currentMonth);
  let currentMonthProgress = 0;
  
  if (currentMonthData) {
    const currentMonthCompleted = currentMonthData.tasks.filter(task => 
      progress.completedTasks[`${progress.currentMonth}-${task.id}`]
    ).length;
    currentMonthProgress = currentMonthData.tasks.length > 0 
      ? Math.round((currentMonthCompleted / currentMonthData.tasks.length) * 100) 
      : 0;
  }
  
  return res.json({
    currentMonth: progress.currentMonth,
    overallProgress,
    completedCount,
    totalTasks,
    currentMonthProgress,
    lastUpdated: progress.lastUpdated
  });
});

app.post('/api/journey/advance', requireAuth, requireRole('ambassador'), (req, res) => {
  try {
    const userId = req.auth.userId;
    let progress = journeyProgressByAmbassador.get(userId);
    
    if (!progress) {
      return res.status(400).json({ error: 'No journey progress found' });
    }
    
    // Check if current month is completed
    const currentMonthData = JOURNEY_MONTHS.find(m => m.month === progress.currentMonth);
    if (!currentMonthData) {
      return res.status(400).json({ error: 'Invalid current month' });
    }
    
    const allTasksCompleted = currentMonthData.tasks.every(task => 
      progress.completedTasks[`${progress.currentMonth}-${task.id}`]
    );
    
    if (!allTasksCompleted) {
      return res.status(400).json({ error: 'Complete all tasks in current month first' });
    }
    
    if (progress.currentMonth >= 12) {
      return res.status(400).json({ error: 'Already at final month' });
    }
    
    // Advance to next month
    progress.currentMonth++;
    progress.monthStartDates[progress.currentMonth] = Date.now();
    progress.lastUpdated = Date.now();
    
    journeyProgressByAmbassador.set(userId, progress);
    saveJourneyToDisk();
    
    return res.json({ 
      success: true, 
      newMonth: progress.currentMonth,
      message: `Advanced to Month ${progress.currentMonth}` 
    });
  } catch (error) {
    console.error('Error advancing month:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/journey/days-remaining', requireAuth, requireRole('ambassador'), (req, res) => {
  const userId = req.auth.userId;
  const progress = journeyProgressByAmbassador.get(userId);
  
  if (!progress) {
    return res.json({ daysRemaining: 365 });
  }
  
  const startDate = new Date(progress.startDate);
  const today = new Date();
  const daysElapsed = Math.floor((today - startDate) / (1000 * 60 * 60 * 24));
  const daysRemaining = Math.max(0, 365 - daysElapsed);
  
  return res.json({ daysRemaining });
});

// ------------------------
// ADMIN Journey Progress APIs
// ------------------------

// Get journey progress for a specific ambassador
app.get('/admin/api/ambassadors/:id/journey', requireAuth, requireRole('admin'), (req, res) => {
  const progress = journeyProgressByAmbassador.get(req.params.id) || {
    currentMonth: 1,
    completedTasks: {},
    startDate: Date.now(),
    monthStartDates: { 1: Date.now() },
    lastUpdated: Date.now()
  };

  // Calculate statistics
  const totalTasks = JOURNEY_MONTHS.reduce((sum, month) => sum + month.tasks.length, 0);
  const completedCount = Object.keys(progress.completedTasks).filter(key => progress.completedTasks[key]).length;
  const overallProgress = totalTasks > 0 ? Math.round((completedCount / totalTasks) * 100) : 0;

  // Get current month info
  const currentMonthData = JOURNEY_MONTHS.find(m => m.month === progress.currentMonth);
  const currentMonthTasks = currentMonthData ? currentMonthData.tasks.length : 0;
  const currentMonthCompleted = currentMonthData 
    ? currentMonthData.tasks.filter(task => progress.completedTasks[`${progress.currentMonth}-${task.id}`]).length 
    : 0;
  const currentMonthProgress = currentMonthTasks > 0 ? Math.round((currentMonthCompleted / currentMonthTasks) * 100) : 0;

  return res.json({
    ambassadorId: req.params.id,
    currentMonth: progress.currentMonth,
    completedTasks: progress.completedTasks,
    startDate: progress.startDate,
    lastUpdated: progress.lastUpdated,
    statistics: {
      totalTasks,
      completedCount,
      overallProgress,
      currentMonthProgress,
      currentMonthTitle: currentMonthData ? currentMonthData.title : 'Unknown',
      currentMonthMilestone: currentMonthData ? currentMonthData.milestone : ''
    },
    months: JOURNEY_MONTHS.map(month => {
      const monthCompleted = month.tasks.filter(task => 
        progress.completedTasks[`${month.month}-${task.id}`]
      ).length;
      const monthProgress = month.tasks.length > 0 
        ? Math.round((monthCompleted / month.tasks.length) * 100) 
        : 0;
      
      return {
        month: month.month,
        title: month.title,
        milestone: month.milestone,
        totalTasks: month.tasks.length,
        completedTasks: monthCompleted,
        progress: monthProgress,
        isCurrentMonth: month.month === progress.currentMonth,
        isCompleted: month.month < progress.currentMonth,
        tasks: month.tasks.map(task => ({
          id: task.id,
          text: task.text,
          completed: !!progress.completedTasks[`${month.month}-${task.id}`],
          critical: task.critical || false,
          time: task.time || '',
          deadline: task.deadline || ''
        }))
      };
    })
  });
});

// Get journey progress summary for all ambassadors
app.get('/admin/api/journey/summary', requireAuth, requireRole('admin'), (req, res) => {
  const ambassadors = [...ambassadorsByEmail.values()].filter(a => a.role === 'ambassador');
  const summary = ambassadors.map(ambassador => {
    const progress = journeyProgressByAmbassador.get(ambassador.id) || {
      currentMonth: 1,
      completedTasks: {},
      startDate: Date.now(),
      lastUpdated: Date.now()
    };

    const totalTasks = JOURNEY_MONTHS.reduce((sum, month) => sum + month.tasks.length, 0);
    const completedCount = Object.keys(progress.completedTasks).filter(key => progress.completedTasks[key]).length;
    const overallProgress = totalTasks > 0 ? Math.round((completedCount / totalTasks) * 100) : 0;

    return {
      ambassadorId: ambassador.id,
      ambassadorName: ambassador.name || ambassador.email,
      ambassadorEmail: ambassador.email,
      currentMonth: progress.currentMonth,
      overallProgress,
      completedTasks: completedCount,
      totalTasks,
      startDate: progress.startDate,
      lastUpdated: progress.lastUpdated || Date.now(),
      status: ambassador.status
    };
  });

  // Sort by last updated (most recent first)
  summary.sort((a, b) => (b.lastUpdated || 0) - (a.lastUpdated || 0));

  return res.json({
    total: summary.length,
    ambassadors: summary
  });
});

// ------------------------
// Admin Dashboard APIs
// ------------------------
app.get('/admin/api/ambassadors', requireAuth, requireRole('admin'), (req, res) => {
  const ambassadors = [...ambassadorsByEmail.values()].filter(a => a.role === 'ambassador');
  
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const statusFilter = req.query.status;
  const search = req.query.search?.toLowerCase();
  
  let filtered = ambassadors;
  
  // Apply search
  if (search) {
    filtered = filtered.filter(amb => 
      amb.name?.toLowerCase().includes(search) || 
      amb.email.toLowerCase().includes(search) ||
      amb.access_code.toLowerCase().includes(search)
    );
  }
  
  // Apply status filter
  if (statusFilter && statusFilter !== 'all') {
    filtered = filtered.filter(amb => amb.status === statusFilter);
  }
  
  // Calculate pagination
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + limit;
  const paginated = filtered.slice(startIndex, endIndex);
  
  // Format response
  const formatted = paginated.map(amb => ({
    id: amb.id,
    name: amb.name,
    email: amb.email,
    access_code: amb.access_code,
    status: amb.status,
    joinDate: amb.joinDate,
    lastLogin: amb.lastLogin,
    profileCompleted: amb.profile?.completed || false
  }));
  
  return res.json({
    ambassadors: formatted,
    total: filtered.length,
    page,
    totalPages: Math.ceil(filtered.length / limit)
  });
});

app.get('/admin/api/ambassadors/:id', requireAuth, requireRole('admin'), (req, res) => {
  const ambassador = [...ambassadorsByEmail.values()].find(a => a.id === req.params.id);
  if (!ambassador) {
    return res.status(404).json({ error: 'Ambassador not found' });
  }
  
  return res.json({
    id: ambassador.id,
    name: ambassador.name,
    email: ambassador.email,
    access_code: ambassador.access_code,
    status: ambassador.status,
    joinDate: ambassador.joinDate,
    lastLogin: ambassador.lastLogin,
    profile: ambassador.profile || {}
  });
});

app.post('/admin/api/ambassadors', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const { name, email, access_code } = req.body;
    
    if (!name || !email || !access_code) {
      return res.status(400).json({ error: 'Name, email, and access code are required' });
    }
    
    const key = email.toLowerCase();
    if (ambassadorsByEmail.has(key)) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Check if access code already exists
    const existingWithCode = [...ambassadorsByEmail.values()].find(a => a.access_code === access_code);
    if (existingWithCode) {
      return res.status(400).json({ error: 'Access code already in use' });
    }
    
    const id = generateId('amb');
    const salt = crypto.randomBytes(8).toString('hex');
    const hashedPassword = hashPassword('welcome123', salt);
    
    const newAmbassador = {
      id,
      name,
      email: key,
      passwordHash: hashedPassword,
      salt,
      access_code: access_code.toUpperCase(),
      role: 'ambassador',
      status: 'active',
      joinDate: new Date().toISOString(),
      lastLogin: null,
      profile: {
        completed: false,
        data: {}
      }
    };
    
    ambassadorsByEmail.set(key, newAmbassador);
    
    // Initialize journey progress
    journeyProgressByAmbassador.set(id, {
      currentMonth: 1,
      completedTasks: {},
      startDate: Date.now(),
      monthStartDates: { 1: Date.now() },
      lastUpdated: Date.now()
    });
    
    saveJourneyToDisk();
    
    return res.json({ 
      success: true, 
      ambassador: {
        id,
        name,
        email,
        access_code: access_code.toUpperCase(),
        status: 'active'
      }
    });
  } catch (error) {
    console.error('Error creating ambassador:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/admin/api/ambassadors/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const { name, email, access_code, status } = req.body;
    const ambassador = [...ambassadorsByEmail.values()].find(a => a.id === req.params.id);
    
    if (!ambassador) {
      return res.status(404).json({ error: 'Ambassador not found' });
    }
    
    // Check if email is being changed and if it's already taken
    if (email && email.toLowerCase() !== ambassador.email.toLowerCase()) {
      const key = email.toLowerCase();
      if (ambassadorsByEmail.has(key)) {
        return res.status(400).json({ error: 'Email already registered' });
      }
      ambassadorsByEmail.delete(ambassador.email.toLowerCase());
      ambassador.email = email.toLowerCase();
      ambassadorsByEmail.set(ambassador.email.toLowerCase(), ambassador);
    }
    
    // Check if access code is being changed and if it's already taken
    if (access_code && access_code !== ambassador.access_code) {
      const existingWithCode = [...ambassadorsByEmail.values()]
        .find(a => a.access_code === access_code && a.id !== ambassador.id);
      if (existingWithCode) {
        return res.status(400).json({ error: 'Access code already in use' });
      }
      ambassador.access_code = access_code;
    }
    
    if (name) ambassador.name = name;
    if (status) ambassador.status = status;
    
    return res.json({ 
      success: true, 
      ambassador: {
        id: ambassador.id,
        name: ambassador.name,
        email: ambassador.email,
        access_code: ambassador.access_code,
        status: ambassador.status
      }
    });
  } catch (error) {
    console.error('Error updating ambassador:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/admin/api/ambassadors/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const ambassador = [...ambassadorsByEmail.values()].find(a => a.id === req.params.id);
    if (!ambassador) {
      return res.status(404).json({ error: 'Ambassador not found' });
    }
    
    ambassadorsByEmail.delete(ambassador.email.toLowerCase());
    
    // Also remove journey progress
    journeyProgressByAmbassador.delete(ambassador.id);
    saveJourneyToDisk();
    
    return res.json({ success: true });
  } catch (error) {
    console.error('Error deleting ambassador:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ------------------------
// Partners APIs
// ------------------------
app.get('/admin/api/partners', requireAuth, requireRole('admin'), (req, res) => {
  const partners = [...partnersByEmail.values()];
  return res.json({ partners });
});

app.post('/admin/api/partners', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const { name, email, company, access_code } = req.body;
    
    if (!name || !email || !access_code) {
      return res.status(400).json({ error: 'Name, email, and access code are required' });
    }
    
    const key = email.toLowerCase();
    if (partnersByEmail.has(key)) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const id = generateId('par');
    const salt = crypto.randomBytes(8).toString('hex');
    const hashedPassword = hashPassword('welcome123', salt);
    
    const newPartner = {
      id,
      name,
      email: email.toLowerCase(),
      company: company || '',
      passwordHash: hashedPassword,
      salt,
      access_code: access_code.toUpperCase(),
      role: 'partner',
      status: 'active',
      joinDate: new Date().toISOString(),
      lastLogin: null
    };
    
    partnersByEmail.set(key, newPartner);
    
    return res.json({ 
      success: true, 
      partner: {
        id,
        name,
        email,
        company,
        access_code: access_code.toUpperCase(),
        status: 'active'
      }
    });
  } catch (error) {
    console.error('Error creating partner:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ------------------------
// Articles APIs
// ------------------------
app.get('/admin/api/articles', requireAuth, requireRole('admin'), (req, res) => {
  const statusFilter = req.query.status;
  
  let filtered = [...articlesById.values()];
  if (statusFilter && statusFilter !== 'all') {
    filtered = filtered.filter(article => article.status === statusFilter);
  }
  
  return res.json({ articles: filtered });
});

app.post('/admin/api/articles', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const { title, excerpt, content, category } = req.body;
    
    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }
    
    const id = generateId('art');
    const newArticle = {
      id,
      title,
      excerpt: excerpt || title.substring(0, 100) + '...',
      content,
      category: category || 'general',
      status: 'draft',
      date: new Date().toISOString(),
      author: req.auth.userId,
      views: 0,
      likes: 0
    };
    
    articlesById.set(id, newArticle);
    saveArticlesToDisk();
    
    return res.json({ success: true, article: newArticle });
  } catch (error) {
    console.error('Error creating article:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/admin/api/articles/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const { title, excerpt, content, category, status } = req.body;
    const article = articlesById.get(req.params.id);
    
    if (!article) {
      return res.status(404).json({ error: 'Article not found' });
    }
    
    if (title) article.title = title;
    if (excerpt) article.excerpt = excerpt;
    if (content) article.content = content;
    if (category) article.category = category;
    if (status) article.status = status;
    
    saveArticlesToDisk();
    
    return res.json({ success: true, article });
  } catch (error) {
    console.error('Error updating article:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/admin/api/articles/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const article = articlesById.get(req.params.id);
    
    if (!article) {
      return res.status(404).json({ error: 'Article not found' });
    }
    
    articlesById.delete(req.params.id);
    saveArticlesToDisk();
    
    return res.json({ success: true });
  } catch (error) {
    console.error('Error deleting article:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ------------------------
// Ambassador Articles
// ------------------------
app.get('/api/articles', requireAuth, requireRole('ambassador'), (req, res) => {
  const publishedArticles = [...articlesById.values()].filter(article => article.status === 'published');
  return res.json({ articles: publishedArticles });
});

app.get('/api/articles/:id', requireAuth, requireRole('ambassador'), (req, res) => {
  const article = articlesById.get(req.params.id);
  if (!article || article.status !== 'published') {
    return res.status(404).json({ error: 'Article not found' });
  }
  
  // Increment views
  article.views = (article.views || 0) + 1;
  saveArticlesToDisk();
  
  return res.json({ article });
});

// ------------------------
// Posts APIs
// ------------------------
app.get('/api/posts', requireAuth, (req, res) => {
  const posts = [...postsById.values()];
  return res.json({ posts });
});

app.post('/api/posts', requireAuth, requireRole('partner'), (req, res) => {
  try {
    const { title, content, category } = req.body;
    
    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }
    
    const id = generateId('post');
    const newPost = {
      id,
      title,
      content,
      category: category || 'general',
      authorId: req.auth.userId,
      authorName: 'Partner',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    postsById.set(id, newPost);
    savePostsToDisk();
    
    return res.json({ success: true, post: newPost });
  } catch (error) {
    console.error('Error creating post:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ------------------------
// CV Upload
// ------------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, CVS_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'cv-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /pdf|doc|docx/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (extname && mimetype) {
      cb(null, true);
    } else {
      cb(new Error('Only PDF, DOC, and DOCX files are allowed'));
    }
  }
});

app.post('/api/upload-cv', requireAuth, requireRole('ambassador'), upload.single('cv'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const user = [...ambassadorsByEmail.values()].find(u => u.id === req.auth.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Remove old CV if exists
    if (user.cvFilename) {
      const oldPath = path.join(CVS_DIR, user.cvFilename);
      if (fs.existsSync(oldPath)) {
        fs.unlinkSync(oldPath);
      }
    }
    
    user.cvFilename = req.file.filename;
    ambassadorsByEmail.set(user.email.toLowerCase(), user);
    
    return res.json({ 
      success: true, 
      filename: req.file.filename,
      message: 'CV uploaded successfully'
    });
  } catch (error) {
    console.error('Error uploading CV:', error);
    return res.status(500).json({ error: 'Failed to upload CV' });
  }
});

// ------------------------
// Notifications
// ------------------------
app.get('/api/notifications', requireAuth, (req, res) => {
  const userId = req.auth.userId;
  const notifications = notificationsByUserId.get(userId) || [];
  
  // Mark all as read
  notifications.forEach(n => n.read = true);
  
  return res.json({ notifications });
});

app.post('/api/notifications/clear', requireAuth, (req, res) => {
  const userId = req.auth.userId;
  notificationsByUserId.set(userId, []);
  return res.json({ success: true });
});

// ------------------------
// Dashboard Stats
// ------------------------
app.get('/api/dashboard/stats', requireAuth, (req, res) => {
  const { role, userId } = req.auth;
  
  if (role === 'ambassador') {
    const user = [...ambassadorsByEmail.values()].find(u => u.id === userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const progress = journeyProgressByAmbassador.get(userId) || {
      currentMonth: 1,
      completedTasks: {},
      startDate: Date.now()
    };
    
    // Calculate journey stats
    const totalTasks = JOURNEY_MONTHS.reduce((sum, month) => sum + month.tasks.length, 0);
    const completedCount = Object.keys(progress.completedTasks).filter(key => progress.completedTasks[key]).length;
    const overallProgress = totalTasks > 0 ? Math.round((completedCount / totalTasks) * 100) : 0;
    
    // Days since joining
    const joinDate = user.joinDate ? new Date(user.joinDate) : new Date();
    const today = new Date();
    const daysInProgram = Math.floor((today - joinDate) / (1000 * 60 * 60 * 24));
    
    return res.json({
      stats: {
        overallProgress,
        completedTasks: completedCount,
        totalTasks,
        currentMonth: progress.currentMonth,
        daysInProgram: Math.max(0, daysInProgram),
        daysRemaining: Math.max(0, 365 - daysInProgram)
      },
      user: {
        name: user.name || 'Ambassador',
        email: user.email,
        joinDate: user.joinDate
      },
      recentArticles: [...articlesById.values()]
        .filter(article => article.status === 'published')
        .slice(0, 3)
        .map(article => ({
          id: article.id,
          title: article.title,
          excerpt: article.excerpt,
          date: article.date,
          category: article.category
        }))
    });
  } else if (role === 'partner') {
    const user = [...partnersByEmail.values()].find(u => u.id === userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    return res.json({
      stats: {
        postsCreated: [...postsById.values()].filter(p => p.authorId === userId).length,
        totalEngagement: 0, // Could track likes/comments
        partnerSince: user.joinDate || new Date().toISOString()
      },
      user: {
        organizationName: user.organizationName,
        contactName: user.contactName,
        email: user.email
      }
    });
  } else if (role === 'admin') {
    return res.json({
      stats: {
        totalAmbassadors: [...ambassadorsByEmail.values()].filter(a => a.role === 'ambassador').length,
        totalPartners: [...partnersByEmail.values()].length,
        totalArticles: articlesById.size,
        activeAmbassadors: [...ambassadorsByEmail.values()].filter(a => a.role === 'ambassador' && a.status === 'active').length
      }
    });
  }
  
  return res.json({ stats: {} });
});

// ------------------------
// Logout
// ------------------------
app.post('/api/logout', async (req, res) => {
  const cookies = parseCookies(req);
  const sid = cookies.sid;
  if (sid) {
    // Delete from database
    await deleteSessionDB(sid);
    // Delete from memory
    sessions.delete(sid);
  }
  clearSessionCookie(res);
  return res.redirect('/signin');
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
  console.log(`[journey] Journey progress tracking ENABLED with REAL-TIME updates`);
  console.log(`[journey] Loaded ${journeyProgressByAmbassador.size} ambassador progress records`);
  console.log(`[data] Data directory: ${DATA_DIR}`);
});
