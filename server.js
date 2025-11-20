const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const multer = require('multer');

const app = express();

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
const postsById = new Map(); // NEW: Store posts
const journeyProgressByAmbassador = new Map();

// ------------------------
// File-based persistence
// ------------------------
const DATA_DIR = path.join(__dirname, 'data');
const ARTICLES_FILE = path.join(DATA_DIR, 'articles.json');
const POSTS_FILE = path.join(DATA_DIR, 'posts.json'); // NEW
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

// NEW: Posts persistence functions
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

const JOURNEY_MONTHS = [
  { month: 1, title: "FOUNDATION", milestone: "Foundation Set: Onboarding complete, first course done, profile submitted, connections made", tasks: [{ id: "linkedin_course", text: "Complete LinkedIn Warrior course", time: "2-3 hours", critical: true }, { id: "submit_profile", text: "Submit profile & speaker materials for audit", deadline: "End of Week 2", critical: true }, { id: "second_course", text: "Choose and start second course (Transformational Leadership)", critical: false }, { id: "connect_10", text: "Connect with 10 Ambassadors on LinkedIn", critical: false }, { id: "post_3x", text: "Post on LinkedIn 3x this month", critical: false }], metrics: { connections: 10, posts: 3, courses: 1 } },
  { month: 2, title: "OPTIMIZE", milestone: "Optimized Presence: Profile updated, first article submitted, active in community", tasks: [{ id: "implement_audit", text: "Implement audit recommendations", critical: true }, { id: "submit_article_1", text: "Submit your first article (4-6 week review)", critical: true }, { id: "engage_15", text: "Engage with 15 ambassador posts this month", critical: false }, { id: "third_course", text: "Start third course: Science of You", critical: false }], metrics: { engagement: 15, articles: 1, courses: 2 } },
  { month: 3, title: "ENGAGE", milestone: "Engaged Member: Attended event, building relationships, consistent content, impact tracked", tasks: [{ id: "first_event", text: "Attend your first quarterly networking event", critical: true }, { id: "follow_up_3", text: "Follow up with 3 people from event (within 48 hours)", critical: true }, { id: "transformation_post", text: "Post transformation update on LinkedIn (90 days)", critical: false }, { id: "submit_article_2", text: "Submit second article (if first is published)", critical: false }, { id: "update_impact_log", text: "Update your impact log", critical: false }], metrics: { impact: 25, events: 1, posts: 3 } },
  { month: 4, title: "LEAD", milestone: "Leadership Activated: Volunteered for opportunity, all courses complete, growing visibility", tasks: [{ id: "volunteer", text: "Volunteer for a leadership opportunity", critical: true }, { id: "complete_courses", text: "Complete all 4 core courses", critical: true }, { id: "request_recommendation", text: "Request letter of recommendation (if needed)", critical: false }, { id: "post_4x", text: "Post 4x on LinkedIn this month", critical: false }], metrics: { courses: 4, posts: 4, leadership: 1 } },
  { month: 5, title: "AMPLIFY", milestone: "Amplified Impact: Led something, article progress, consistent support", tasks: [{ id: "lead_something", text: "Lead or co-lead something (book club, session, event)", critical: true }, { id: "check_article", text: "Check article status and take action", critical: true }, { id: "daily_engage", text: "Engage with Ambassadors content daily (5 min/day)", critical: false }, { id: "update_impact_5", text: "Update impact log", critical: false }], metrics: { impact: 45, leadership: 2, engagement: 150 } },
  { month: 6, title: "MIDPOINT", milestone: "Halfway Strong: Story shared, podcast scheduled, 50+ people impacted, momentum building", tasks: [{ id: "quarterly_event_2", text: "Attend quarterly networking event", critical: true }, { id: "review_progress", text: "Review your 6-month progress", critical: true }, { id: "schedule_podcast", text: "Schedule your podcast episode", critical: true }, { id: "halfway_story", text: "Post your halfway transformation story", critical: false }], metrics: { impact: 50, events: 2, podcast: 1 } },
  { month: 7, title: "VISIBILITY", milestone: "Visible Leader: Podcast prep underway, leading regularly, strong content cadence", tasks: [{ id: "prep_podcast", text: "Prep for podcast recording", critical: true }, { id: "submit_article_next", text: "Submit next article (if you haven't already)", critical: false }, { id: "lead_second", text: "Host or lead a second opportunity", critical: false }, { id: "post_4x_m7", text: "Post consistently: 4x this month", critical: false }], metrics: { posts: 4, leadership: 3, articles: 2 } },
  { month: 8, title: "EXPAND", milestone: "Expanded Reach: Podcast recorded/scheduled, applied for external opportunities, portfolio growing", tasks: [{ id: "record_podcast", text: "Record podcast episode (if scheduled this month)", critical: true }, { id: "check_partners", text: "Check T4L Partners portal weekly", critical: false }, { id: "update_speaker", text: "Update speaker materials", critical: false }, { id: "speaking_pitch", text: "Submit speaking pitch (outside T4L)", critical: false }, { id: "update_impact_8", text: "Update impact log", critical: false }], metrics: { impact: 70, opportunities: 2 } },
  { month: 9, title: "CONNECT", milestone: "Connected Leader: Deep relationships built, podcast live, third leadership opportunity completed", tasks: [{ id: "quarterly_event_3", text: "Attend quarterly networking event", critical: true }, { id: "follow_up_5", text: "Follow up with 5 people from event", critical: true }, { id: "promote_podcast", text: "Promote podcast episode (when it drops)", critical: false }, { id: "lead_third", text: "Lead or volunteer for third opportunity", critical: false }], metrics: { events: 3, leadership: 4, connections: 50 } },
  { month: 10, title: "ACCELERATE", milestone: "Accelerating: Final articles submitted, 85+ impacted, speaking opportunities in pipeline", tasks: [{ id: "submit_final", text: "Submit final articles", critical: true }, { id: "update_impact_10", text: "Update impact log", critical: true }, { id: "post_impact", text: "Post about your impact journey", critical: false }, { id: "apply_speaking", text: "Apply for 2+ speaking opportunities", critical: false }], metrics: { impact: 85, articles: 4, opportunities: 4 } },
  { month: 11, title: "CELEBRATE", milestone: "Celebrating: Year documented, story shared, impact quantified", tasks: [{ id: "quarterly_event_4", text: "Attend quarterly event", critical: true }, { id: "final_impact", text: "Complete final impact log", critical: true }, { id: "transformation_story", text: "Post full year transformation story", critical: false }, { id: "update_bio", text: "Update bio for event spotlight", critical: false }], metrics: { impact: 100, events: 4 } },
  { month: 12, title: "RENEW", milestone: "Transformation Complete: Full year tracked, portfolio built, thought leadership established, decision made", tasks: [{ id: "review_year", text: "Review your year (articles, sessions, courses, impact)", critical: true }, { id: "update_materials", text: "Update all materials (LinkedIn, speaker sheet, portfolio)", critical: true }, { id: "decide_renewal", text: "Decide on renewal (Top Voices, free tier, or alumni)", critical: false }, { id: "schedule_call", text: "Schedule renewal call with T4L", critical: false }], metrics: { impact: 100, articles: 4, leadership: 4, courses: 4 } }
];

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
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
}

function getSession(req) {
  const cookies = parseCookies(req);
  const sid = cookies.sid;
  if (!sid) return null;
  const sess = sessions.get(sid);
  if (!sess) return null;
  if (sess.expiresAt && Date.now() > sess.expiresAt) {
    sessions.delete(sid);
    return null;
  }
  return { sid, ...sess };
}

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
function requireAuth(req, res, next) {
  const sess = getSession(req);
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

function listUsers(map, { query = '', status, limit = 20, offset = 0 }) {
  const normalizedQuery = String(query || '').trim().toLowerCase();
  const normalizedStatus = status ? String(status).toLowerCase() : undefined;
  const all = [...map.values()];
  const filtered = all.filter(u => {
    const matchQuery = !normalizedQuery || (u.email && u.email.toLowerCase().includes(normalizedQuery)) ||
      (u.name && String(u.name).toLowerCase().includes(normalizedQuery)) ||
      (u.organizationName && String(u.organizationName).toLowerCase().includes(normalizedQuery)) ||
      (u.contactName && String(u.contactName).toLowerCase().includes(normalizedQuery));
    const matchStatus = !normalizedStatus || (u.status && String(u.status).toLowerCase() === normalizedStatus);
    return matchQuery && matchStatus;
  });
  const total = filtered.length;
  const items = filtered.slice(offset, offset + limit).map(u => ({
    id: u.id,
    email: u.email,
    role: u.role,
    status: u.status,
    name: u.name || u.contactName || null,
    organizationName: u.organizationName || null
  }));
  return { total, items, limit, offset };
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
  accessCode: 'T4LA-1234',
  status: 'active',
  salt: crypto.randomBytes(8).toString('hex')
};
TEST_AMBASSADOR.passwordHash = hashPassword('password123', TEST_AMBASSADOR.salt);

const TEST_PARTNER = {
  id: generateId('par'),
  role: 'partner',
  email: 'partner@test.com',
  accessCode: 'T4LP-5678',
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
  accessCode: 'T4LA-ADMIN',
  status: 'active',
  salt: crypto.randomBytes(8).toString('hex')
};
TEST_ADMIN.passwordHash = hashPassword('password123', TEST_ADMIN.salt);
adminsByEmail.set(TEST_ADMIN.email.toLowerCase(), TEST_ADMIN);

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
app.post('/register/ambassador', (req, res) => {
  const { email, accessCode, password, name } = req.body || {};
  if (!email || !accessCode || !password || !name) {
    return res.status(400).json({ error: 'All fields required' });
  }
  const key = String(email).toLowerCase();
  if (ambassadorsByEmail.has(key)) {
    return res.status(409).json({ error: 'Ambassador already exists' });
  }
  const salt = crypto.randomBytes(8).toString('hex');
  const user = {
    id: generateId('amb'),
    role: 'ambassador',
    email: key,
    accessCode,
    name,
    status: 'active',
    salt,
    passwordHash: hashPassword(password, salt)
  };
  ambassadorsByEmail.set(key, user);
  return res.redirect('/signin?autoPopulate=true');
});

app.post('/register/partner', (req, res) => {
  const { email, accessCode, password, organizationName, contactName } = req.body || {};
  if (!email || !accessCode || !password || !organizationName || !contactName) {
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
    accessCode,
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
app.post('/signin', (req, res) => {
  const { email, accessCode, password, rememberMe } = req.body || {};
  const key = (email || '').toLowerCase();
  const user = ambassadorsByEmail.get(key);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.accessCode !== accessCode) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const computed = hashPassword(String(password || ''), user.salt);
  if (computed !== user.passwordHash) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.status !== 'active') {
    return res.status(403).json({ error: 'Account inactive' });
  }
  createSession(res, user.id, 'ambassador', Boolean(rememberMe));
  return res.redirect('/ambassador-dashboard.html');
});

app.post('/partner-signin', (req, res) => {
  const { email, accessCode, password, rememberMe } = req.body || {};
  const key = (email || '').toLowerCase();
  const user = partnersByEmail.get(key);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.accessCode !== accessCode) {
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
  const { email, accessCode, password, rememberMe } = req.body || {};
  const key = (email || '').toLowerCase();
  const user = adminsByEmail.get(key);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.accessCode !== accessCode) {
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
  const acceptsHtml = (req.headers['accept'] || '').includes('text/html');
  if (acceptsHtml) return res.redirect('/admin-dashboard.html');
  return res.json({ ok: true, role: 'admin' });
});

// ------------------------
// Protected Pages
// ------------------------
app.get('/ambassador-dashboard.html', requireAuth, requireRole('ambassador'), (req, res) => {
  const user = [...ambassadorsByEmail.values()].find(u => u.id === req.auth.userId);
  if (!user) {
    return res.redirect('/signin');
  }
  res.sendFile(path.join(__dirname, 'public', 'ambassador-dashboard.html'));
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
  // Profile page is accessible to all authenticated users
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

// Additional protected pages
app.get('/article-amb.html', requireAuth, requireRole('ambassador'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'article-amb.html'));
});

app.get('/article-progress.html', requireAuth, requireRole('ambassador'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'article-progress.html'));
});

app.get('/Partner-Calls.html', requireAuth, (req, res) => {
  // Accessible to both ambassadors and partners
  res.sendFile(path.join(__dirname, 'public', 'Partner-Calls.html'));
});

app.get('/journey.html', requireAuth, requireRole('ambassador'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'journey.html'));
});

app.get('/chat-pillar.html', requireAuth, (req, res) => {
  // Accessible to all authenticated users
  res.sendFile(path.join(__dirname, 'public', 'chat-pillar.html'));
});

app.get('/chat-region.html', requireAuth, (req, res) => {
  // Accessible to all authenticated users
  res.sendFile(path.join(__dirname, 'public', 'chat-region.html'));
});

app.get('/creat-Post.html', requireAuth, requireRole('partner'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'creat-Post.html'));
});

app.get('/CommunityPartView.html', requireAuth, (req, res) => {
  // Accessible to all authenticated users
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

// Get full profile data
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
    accessCode: user.accessCode
  };
  
  // Add role-specific fields
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

// Update profile
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
  
  // Update fields based on role
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
  
  // Save back to map
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

// Change password
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
  
  // Verify current password
  const computed = hashPassword(String(currentPassword || ''), user.salt);
  if (computed !== user.passwordHash) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  
  // Update password
  user.passwordHash = hashPassword(newPassword, user.salt);
  
  // Save back to map
  const emailKey = user.email.toLowerCase();
  userMap.set(emailKey, user);
  
  return res.json({ ok: true, message: 'Password updated successfully' });
});

// CV Upload Configuration
const cvStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    ensureDataDir(); // Ensure directory exists
    cb(null, CVS_DIR);
  },
  filename: function (req, file, cb) {
    // Generate unique filename: userId_timestamp.extension
    const { userId } = req.auth;
    const timestamp = Date.now();
    const ext = path.extname(file.originalname);
    const filename = `${userId}_${timestamp}${ext}`;
    cb(null, filename);
  }
});

const cvUpload = multer({
  storage: cvStorage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: function (req, file, cb) {
    // Accept PDF, DOC, DOCX files
    const allowedMimes = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    const allowedExts = ['.pdf', '.doc', '.docx'];
    
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedMimes.includes(file.mimetype) && allowedExts.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF, DOC, and DOCX files are allowed.'));
    }
  }
});

// Upload CV (Ambassadors only)
app.post('/api/profile/cv', requireAuth, requireRole('ambassador'), (req, res) => {
  cvUpload.single('cv')(req, res, function(err) {
    // Handle multer errors
    if (err) {
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({ error: 'File size exceeds 10MB limit' });
        }
        return res.status(400).json({ error: err.message || 'File upload error' });
      }
      // File filter error or other errors
      return res.status(400).json({ error: err.message || 'Invalid file type' });
    }
    
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const { userId } = req.auth;
    const user = [...ambassadorsByEmail.values()].find(u => u.id === userId);
    
    if (!user) {
      // Delete the uploaded file if user not found
      try {
        if (fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path);
        }
      } catch (unlinkErr) {
        console.warn('[cv] Failed to delete uploaded file:', unlinkErr && unlinkErr.message ? unlinkErr.message : unlinkErr);
      }
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Delete old CV file if exists
    if (user.cvFilename) {
      const oldCvPath = path.join(CVS_DIR, user.cvFilename);
      try {
        if (fs.existsSync(oldCvPath)) {
          fs.unlinkSync(oldCvPath);
        }
      } catch (err) {
        console.warn('[cv] Failed to delete old CV:', err && err.message ? err.message : err);
      }
    }
    
    // Update user with new CV filename
    user.cvFilename = req.file.filename;
    const emailKey = user.email.toLowerCase();
    ambassadorsByEmail.set(emailKey, user);
    
    console.log(`[cv] CV uploaded for ambassador ${userId}: ${req.file.filename}`);
    
    return res.json({ ok: true, filename: req.file.filename, message: 'CV uploaded successfully' });
  });
});

// ------------------------
// NEW: Posts API Endpoints
// ------------------------

// Create a new post (Partners only)
app.post('/api/posts', requireAuth, requireRole('partner'), (req, res) => {
  const { postType, title, description, format, location, deadline, liftPillars } = req.body || {};
  
  // Validation
  if (!postType || !title || !description || !format || !deadline) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  if (!liftPillars || !Array.isArray(liftPillars) || liftPillars.length === 0) {
    return res.status(400).json({ error: 'At least one LIFT pillar is required' });
  }
  
  // Get partner info
  const partner = [...partnersByEmail.values()].find(u => u.id === req.auth.userId);
  if (!partner) {
    return res.status(404).json({ error: 'Partner not found' });
  }
  
  // Create post
  const id = generateId('post');
  const post = {
    id,
    postType: String(postType).trim(),
    title: String(title).trim(),
    description: String(description).trim(),
    format: String(format).trim(),
    location: location ? String(location).trim() : null,
    deadline: String(deadline).trim(),
    liftPillars: liftPillars.map(p => String(p).trim()),
    partnerId: req.auth.userId,
    partnerName: partner.organizationName || partner.contactName || 'Partner',
    createdAt: Date.now(),
    likes: 0,
    comments: 0,
    views: 0,
    spotsAvailable: 5
  };
  
  postsById.set(id, post);
  savePostsToDisk();
  
  console.log(`[posts] Created new post: ${id} by ${post.partnerName}`);
  
  return res.status(201).json({ ok: true, id, post });
});

// Get all posts (public-ish, but requires auth)
app.get('/api/posts', requireAuth, (req, res) => {
  const { postType, liftPillar, limit, offset } = req.query || {};
  
  const l = parseIntParam(limit, 20);
  const o = parseIntParam(offset, 0);
  
  let items = [...postsById.values()];
  
  // Filter by post type if provided
  if (postType) {
    const normalizedType = String(postType).toLowerCase();
    items = items.filter(p => String(p.postType).toLowerCase() === normalizedType);
  }
  
  // Filter by LIFT pillar if provided
  if (liftPillar) {
    const normalizedPillar = String(liftPillar).toLowerCase();
    items = items.filter(p => 
      p.liftPillars && p.liftPillars.some(pillar => 
        String(pillar).toLowerCase().includes(normalizedPillar)
      )
    );
  }
  
  // Sort by creation date (newest first)
  items.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  
  const total = items.length;
  const page = items.slice(o, o + l);
  
  return res.json({ total, items: page, limit: l, offset: o });
});

// Get single post
app.get('/api/posts/:id', requireAuth, (req, res) => {
  const post = postsById.get(req.params.id);
  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }
  
  // Increment view count
  post.views = (post.views || 0) + 1;
  savePostsToDisk();
  
  return res.json(post);
});

// Update post (Partner who created it only)
app.patch('/api/posts/:id', requireAuth, requireRole('partner'), (req, res) => {
  const post = postsById.get(req.params.id);
  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }
  
  if (post.partnerId !== req.auth.userId) {
    return res.status(403).json({ error: 'You can only edit your own posts' });
  }
  
  const { title, description, format, location, deadline, liftPillars, spotsAvailable } = req.body || {};
  
  if (title) post.title = String(title).trim();
  if (description) post.description = String(description).trim();
  if (format) post.format = String(format).trim();
  if (location !== undefined) post.location = location ? String(location).trim() : null;
  if (deadline) post.deadline = String(deadline).trim();
  if (liftPillars && Array.isArray(liftPillars)) {
    post.liftPillars = liftPillars.map(p => String(p).trim());
  }
  if (spotsAvailable !== undefined) post.spotsAvailable = parseIntParam(spotsAvailable, 5);
  
  post.updatedAt = Date.now();
  
  savePostsToDisk();
  
  return res.json({ ok: true, post });
});

// Delete post (Partner who created it only)
app.delete('/api/posts/:id', requireAuth, requireRole('partner'), (req, res) => {
  const post = postsById.get(req.params.id);
  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }
  
  if (post.partnerId !== req.auth.userId) {
    return res.status(403).json({ error: 'You can only delete your own posts' });
  }
  
  postsById.delete(req.params.id);
  savePostsToDisk();
  
  return res.status(204).send();
});

// ------------------------
// NEW: Applications API Endpoints
// ------------------------

// Store applications in memory
const applicationsByPostId = new Map();
const applicationsByPartnerId = new Map();

// Submit application (Ambassadors)
app.post('/api/applications', requireAuth, requireRole('ambassador'), (req, res) => {
  const { postId, coverLetter, additionalInfo } = req.body || {};
  
  if (!postId) {
    return res.status(400).json({ error: 'Post ID is required' });
  }
  
  // Get post details
  const post = postsById.get(postId);
  if (!post) {
    return res.status(404).json({ error: 'Opportunity not found' });
  }
  
  // Get ambassador profile with CV
  const ambassador = [...ambassadorsByEmail.values()].find(u => u.id === req.auth.userId);
  if (!ambassador) {
    return res.status(404).json({ error: 'Ambassador not found' });
  }
  
  // Create application
  const applicationId = generateId('app');
  const application = {
    id: applicationId,
    postId,
    postTitle: post.title,
    postType: post.postType,
    partnerId: post.partnerId,
    partnerName: post.partnerName,
    ambassadorId: req.auth.userId,
    ambassadorName: ambassador.name || 'Ambassador',
    ambassadorEmail: ambassador.email,
    ambassadorProfile: {
      name: ambassador.name,
      email: ambassador.email,
      accessCode: ambassador.accessCode,
      cvFilename: ambassador.cvFilename,
      // Include any other relevant profile data
    },
    coverLetter: coverLetter || '',
    additionalInfo: additionalInfo || '',
    status: 'pending',
    appliedAt: Date.now()
  };
  
  // Store application
  if (!applicationsByPostId.has(postId)) {
    applicationsByPostId.set(postId, []);
  }
  applicationsByPostId.get(postId).push(application);
  
  if (!applicationsByPartnerId.has(post.partnerId)) {
    applicationsByPartnerId.set(post.partnerId, []);
  }
  applicationsByPartnerId.get(post.partnerId).push(application);
  
  console.log(`[applications] New application from ${ambassador.name} for ${post.title}`);
  
  return res.status(201).json({ 
    ok: true, 
    applicationId,
    message: 'Application submitted successfully!' 
  });
});

// Get applications for a partner
app.get('/api/partner/applications', requireAuth, requireRole('partner'), (req, res) => {
  const { status, limit, offset } = req.query || {};
  
  const partnerApplications = applicationsByPartnerId.get(req.auth.userId) || [];
  
  // Filter by status if provided
  let filteredApplications = partnerApplications;
  if (status && status !== 'all') {
    filteredApplications = partnerApplications.filter(app => app.status === status);
  }
  
  // Sort by most recent
  filteredApplications.sort((a, b) => b.appliedAt - a.appliedAt);
  
  const l = parseIntParam(limit, 20);
  const o = parseIntParam(offset, 0);
  const total = filteredApplications.length;
  const items = filteredApplications.slice(o, o + l);
  
  return res.json({ total, items, limit: l, offset: o });
});

// Get application details with ambassador CV
app.get('/api/partner/applications/:id', requireAuth, requireRole('partner'), (req, res) => {
  const allApplications = applicationsByPartnerId.get(req.auth.userId) || [];
  const application = allApplications.find(app => app.id === req.params.id);
  
  if (!application) {
    return res.status(404).json({ error: 'Application not found' });
  }
  
  // Get ambassador data including CV
  const ambassador = [...ambassadorsByEmail.values()].find(u => u.id === application.ambassadorId);
  if (ambassador && ambassador.cvFilename) {
    application.ambassadorProfile.cvUrl = `/uploads/cvs/${ambassador.cvFilename}`;
  }
  
  return res.json(application);
});

// Update application status (Partner)
app.patch('/api/partner/applications/:id', requireAuth, requireRole('partner'), (req, res) => {
  const { status } = req.body || {};
  
  if (!['pending', 'reviewed', 'accepted', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  
  const allApplications = applicationsByPartnerId.get(req.auth.userId) || [];
  const applicationIndex = allApplications.findIndex(app => app.id === req.params.id);
  
  if (applicationIndex === -1) {
    return res.status(404).json({ error: 'Application not found' });
  }
  
  allApplications[applicationIndex].status = status;
  allApplications[applicationIndex].updatedAt = Date.now();
  
  // Also update in post-based storage
  const postApplications = applicationsByPostId.get(allApplications[applicationIndex].postId) || [];
  const postAppIndex = postApplications.findIndex(app => app.id === req.params.id);
  if (postAppIndex !== -1) {
    postApplications[postAppIndex].status = status;
    postApplications[postAppIndex].updatedAt = Date.now();
  }
  
  return res.json({ ok: true, application: allApplications[applicationIndex] });
});

// ------------------------
// Admin Management APIs
// ------------------------
app.get('/admin/api/ambassadors', requireAuth, requireRole('admin'), (req, res) => {
  const { q, status, limit, offset } = req.query || {};
  const out = listUsers(ambassadorsByEmail, {
    query: q,
    status,
    limit: parseIntParam(limit, 20),
    offset: parseIntParam(offset, 0)
  });
  return res.json(out);
});

app.get('/admin/api/partners', requireAuth, requireRole('admin'), (req, res) => {
  const { q, status, limit, offset } = req.query || {};
  const out = listUsers(partnersByEmail, {
    query: q,
    status,
    limit: parseIntParam(limit, 20),
    offset: parseIntParam(offset, 0)
  });
  return res.json(out);
});

app.get('/admin/api/ambassadors/:id', requireAuth, requireRole('admin'), (req, res) => {
  const user = [...ambassadorsByEmail.values()].find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  return res.json(user);
});

app.get('/admin/api/partners/:id', requireAuth, requireRole('admin'), (req, res) => {
  const user = [...partnersByEmail.values()].find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  return res.json(user);
});

app.patch('/admin/api/ambassadors/:id', requireAuth, requireRole('admin'), (req, res) => {
  const { status, name, accessCode } = req.body || {};
  const key = [...ambassadorsByEmail.keys()].find(k => ambassadorsByEmail.get(k).id === req.params.id);
  if (!key) return res.status(404).json({ error: 'Not found' });
  const user = ambassadorsByEmail.get(key);
  if (typeof status === 'string') user.status = status;
  if (typeof name === 'string') user.name = name;
  if (typeof accessCode === 'string') user.accessCode = accessCode;
  return res.json({ ok: true, user });
});

app.patch('/admin/api/partners/:id', requireAuth, requireRole('admin'), (req, res) => {
  const { status, organizationName, contactName, accessCode } = req.body || {};
  const key = [...partnersByEmail.keys()].find(k => partnersByEmail.get(k).id === req.params.id);
  if (!key) return res.status(404).json({ error: 'Not found' });
  const user = partnersByEmail.get(key);
  if (typeof status === 'string') user.status = status;
  if (typeof organizationName === 'string') user.organizationName = organizationName;
  if (typeof contactName === 'string') user.contactName = contactName;
  if (typeof accessCode === 'string') user.accessCode = accessCode;
  return res.json({ ok: true, user });
});

app.delete('/admin/api/ambassadors/:id', requireAuth, requireRole('admin'), (req, res) => {
  const key = [...ambassadorsByEmail.keys()].find(k => ambassadorsByEmail.get(k).id === req.params.id);
  if (!key) return res.status(404).json({ error: 'Not found' });
  ambassadorsByEmail.delete(key);
  return res.status(204).send();
});

app.delete('/admin/api/partners/:id', requireAuth, requireRole('admin'), (req, res) => {
  const key = [...partnersByEmail.keys()].find(k => partnersByEmail.get(k).id === req.params.id);
  if (!key) return res.status(404).json({ error: 'Not found' });
  partnersByEmail.delete(key);
  return res.status(204).send();
});

// ------------------------
// Article APIs - UPDATED WITH BYLINE SUPPORT
// ------------------------
app.post('/api/ambassador/articles', requireAuth, requireRole('ambassador'), (req, res) => {
  const { title, contentHtml, byline } = req.body || {};
  if (!title || !String(title).trim()) return res.status(400).json({ error: 'Title is required' });
  if (!contentHtml || !String(contentHtml).trim()) return res.status(400).json({ error: 'Content is required' });
  if (!byline || !String(byline).trim()) return res.status(400).json({ error: 'Byline is required' });

  const id = generateId('art');
  const article = {
    id,
    title: String(title).trim(),
    contentHtml: String(contentHtml).trim(),
    byline: String(byline).trim(),
    ambassadorId: req.auth.userId,
    status: 'pending',
    createdAt: Date.now()
  };
  articlesById.set(id, article);
  saveArticlesToDisk();
  return res.status(201).json({ ok: true, id, status: article.status });
});

app.get('/api/ambassador/articles', requireAuth, requireRole('ambassador'), (req, res) => {
  const { limit, offset } = req.query || {};
  const l = parseIntParam(limit, 20);
  const o = parseIntParam(offset, 0);
  const items = [...articlesById.values()]
    .filter(a => a.ambassadorId === req.auth.userId)
    .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)); // Sort by newest first
  const total = items.length;
  const page = items.slice(o, o + l);
  return res.json({ total, items: page, limit: l, offset: o });
});

app.get('/api/ambassador/articles/:id', requireAuth, requireRole('ambassador'), (req, res) => {
  const art = articlesById.get(req.params.id);
  if (!art || art.ambassadorId !== req.auth.userId) return res.status(404).json({ error: 'Not found' });
  
  const notifications = (notificationsByUserId.get(req.auth.userId) || [])
    .filter(n => String(n.articleId) === String(art.id))
    .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  
  return res.json({
    article: art,
    notifications: notifications
  });
});

// ✅ UPDATED PATCH ENDPOINT FOR BYLINE SUPPORT
app.patch('/api/ambassador/articles/:id', requireAuth, requireRole('ambassador'), (req, res) => {
  const { title, contentHtml, byline, status } = req.body || {};
  const art = articlesById.get(req.params.id);
  
  if (!art || art.ambassadorId !== req.auth.userId) {
    return res.status(404).json({ error: 'Not found' });
  }

  // Update fields if provided
  if (typeof title === 'string' && title.trim()) {
    art.title = title.trim();
  }
  if (typeof contentHtml === 'string' && contentHtml.trim()) {
    art.contentHtml = contentHtml.trim();
  }
  if (typeof byline === 'string' && byline.trim()) {
    art.byline = byline.trim();
  }
  if (typeof status === 'string') {
    art.status = status;
  }

  art.updatedAt = Date.now();
  saveArticlesToDisk();

  return res.json({ 
    ok: true, 
    article: art,
    message: 'Article updated successfully'
  });
});

// ADMIN ARTICLES API - UPDATED FOR BYLINE SUPPORT
app.get('/admin/api/articles', requireAuth, requireRole('admin'), (req, res) => {
  const { status, q, limit, offset } = req.query || {};
  const normalizedStatus = status ? String(status).toLowerCase() : '';
  const normalizedQuery = q ? String(q).toLowerCase().trim() : '';
  
  // Get all articles and filter
  let items = [...articlesById.values()];
  
  // Filter by status if provided
  if (normalizedStatus) {
    items = items.filter(a => String(a.status).toLowerCase() === normalizedStatus);
  }
  
  // Filter by search query if provided
  if (normalizedQuery) {
    items = items.filter(a => {
      const searchable = [
        a.title,
        a.byline,
        a.contentHtml
      ].map(v => (v || '').toString().toLowerCase()).join(' ');
      return searchable.includes(normalizedQuery);
    });
  }
  
  // Sort by createdAt descending (newest first)
  items.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  
  const total = items.length;
  const l = parseIntParam(limit, 20);
  const o = parseIntParam(offset, 0);
  const page = items.slice(o, o + l);
  
  return res.json({ total, items: page, limit: l, offset: o });
});

app.get('/admin/api/articles/:id', requireAuth, requireRole('admin'), (req, res) => {
  const art = articlesById.get(req.params.id);
  if (!art) return res.status(404).json({ error: 'Not found' });
  return res.json(art);
});

app.patch('/admin/api/articles/:id', requireAuth, requireRole('admin'), (req, res) => {
  const { status } = req.body || {};
  const art = articlesById.get(req.params.id);
  if (!art) return res.status(404).json({ error: 'Not found' });
  if (typeof status === 'string') art.status = status;
  saveArticlesToDisk();
  return res.json({ ok: true, article: art });
});

app.delete('/admin/api/articles/:id', requireAuth, requireRole('admin'), (req, res) => {
  const art = articlesById.get(req.params.id);
  if (!art) return res.status(404).json({ error: 'Not found' });
  articlesById.delete(req.params.id);
  saveArticlesToDisk();
  return res.status(204).send();
});

app.post('/admin/api/notifications', requireAuth, requireRole('admin'), (req, res) => {
  const { articleId, type, message } = req.body || {};
  if (!articleId || !type) {
    return res.status(400).json({ error: 'articleId and type are required' });
  }
  const art = articlesById.get(String(articleId));
  if (!art) return res.status(404).json({ error: 'Article not found' });
  const userId = art.ambassadorId;
  
  const admin = [...adminsByEmail.values()].find(a => a.id === req.auth.userId);
  const adminName = admin ? (admin.name || admin.email || 'Admin') : 'Admin';
  
  const notif = {
    id: generateId('ntf'),
    userId,
    articleId: art.id,
    type: String(type),
    message: typeof message === 'string' ? message : '',
    adminId: req.auth.userId,
    adminName: adminName,
    createdAt: Date.now()
  };
  const arr = notificationsByUserId.get(userId) || [];
  arr.push(notif);
  notificationsByUserId.set(userId, arr);
  
  if (String(type).toLowerCase() === 'needs_update') {
    art.status = 'needs_update';
    saveArticlesToDisk();
  }
  
  return res.json({ ok: true, notificationId: notif.id });
});

app.get('/admin/api/articles/:id/notifications', requireAuth, requireRole('admin'), (req, res) => {
  const art = articlesById.get(req.params.id);
  if (!art) return res.status(404).json({ error: 'Article not found' });
  
  const allNotifications = [];
  for (const [userId, notifications] of notificationsByUserId.entries()) {
    const articleNotifs = notifications.filter(n => String(n.articleId) === String(art.id));
    allNotifications.push(...articleNotifs);
  }
  
  allNotifications.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  
  return res.json({ total: allNotifications.length, items: allNotifications });
});

app.get('/api/notifications', requireAuth, (req, res) => {
  const userId = req.auth.userId;
  const arr = notificationsByUserId.get(userId) || [];
  const { limit, offset } = req.query || {};
  const l = parseIntParam(limit, 50);
  const o = parseIntParam(offset, 0);
  const total = arr.length;
  const items = arr.slice(o, o + l);
  return res.json({ total, items, limit: l, offset: o });
});

// ------------------------
// Journey API Endpoints
// ------------------------
app.get('/api/ambassador/journey', requireAuth, requireRole('ambassador'), (req, res) => {
  const progress = journeyProgressByAmbassador.get(req.auth.userId) || { currentMonth: 1, completedTasks: {}, startDate: Date.now() };

  return res.json({ currentMonth: progress.currentMonth, completedTasks: progress.completedTasks, months: JOURNEY_MONTHS });
});

app.post('/api/ambassador/journey/toggle', requireAuth, requireRole('ambassador'), (req, res) => {
  const { monthIndex, taskId } = req.body || {};

  if (monthIndex === undefined || !taskId) return res.status(400).json({ error: 'monthIndex and taskId required' });

  const progress = journeyProgressByAmbassador.get(req.auth.userId) || { currentMonth: 1, completedTasks: {}, startDate: Date.now() };

  const key = `${monthIndex}-${taskId}`;

  progress.completedTasks[key] = !progress.completedTasks[key];

  progress.lastUpdated = Date.now();

  journeyProgressByAmbassador.set(req.auth.userId, progress);

  saveJourneyToDisk();

  return res.json({ ok: true, completedTasks: progress.completedTasks });
});

app.post('/api/ambassador/journey/next-month', requireAuth, requireRole('ambassador'), (req, res) => {
  const progress = journeyProgressByAmbassador.get(req.auth.userId) || { currentMonth: 1, completedTasks: {}, startDate: Date.now() };

  if (progress.currentMonth >= 12) return res.status(400).json({ error: 'Journey complete' });

  progress.currentMonth += 1;

  progress.lastUpdated = Date.now();

  journeyProgressByAmbassador.set(req.auth.userId, progress);

  saveJourneyToDisk();

  return res.json({ ok: true, currentMonth: progress.currentMonth });
});

// ------------------------
// Logout
// ------------------------
app.post('/logout', (req, res) => {
  const sess = getSession(req);
  if (sess) {
    sessions.delete(sess.sid);
  }
  clearSessionCookie(res);
  return res.status(204).send();
});

// ------------------------
// Startup
// ------------------------
const PORT = process.env.PORT || 3000;

// Load persisted data before starting the server
loadArticlesFromDisk();
loadPostsFromDisk(); // NEW: Load posts
loadJourneyFromDisk();

app.listen(PORT, () => {
  console.log(`\nServer running at http://localhost:${PORT}`);
  console.log(`Open: http://localhost:${PORT}\n`);
  console.log('Test credentials:');
  console.log('- Ambassador: ambassador@test.com / T4LA-1234 / password123');
  console.log('- Partner: partner@test.com / T4LP-5678 / password123');
  console.log('- Admin: admin@test.com / T4LA-ADMIN / password123');
  console.log('\nNotes: In-memory storage with file persistence for articles and posts.');
});