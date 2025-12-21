const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { connect } = require('../src/db');
const { User, MedicalRecord } = require('../src/models');
const { seedPatched } = require('./seed');

const app = express();
app.use(bodyParser.json());

const JWT_SECRET = process.env.JWT_SECRET || 'reol-patched-secret';

// helper: detect $ operators in objects
function containsOperator(obj) {
  if (typeof obj !== 'object' || obj === null) return false;
  for (const k of Object.keys(obj)) {
    if (k.startsWith('$')) return true;
    if (typeof obj[k] === 'object') {
      if (containsOperator(obj[k])) return true;
    }
  }
  return false;
}

// escape regex special chars
function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function signToken(user) {
  return jwt.sign({ sub: user._id, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
}

function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Missing authorization header' });
  const token = auth.replace('Bearer ', '');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ message: 'Access denied' });
    next();
  };
}

// Simple in-memory rate limiter for login attempts per username
const loginAttempts = new Map();
function tooManyAttempts(username) {
  const attempt = loginAttempts.get(username) || { count: 0, first: Date.now() };
  const windowMs = 15 * 60 * 1000; // 15 minutes
  if (Date.now() - attempt.first > windowMs) {
    attempt.count = 0; attempt.first = Date.now();
  }
  attempt.count += 1;
  loginAttempts.set(username, attempt);
  return attempt.count > 5;
}

function maskSSN(ssn) {
  if (!ssn || typeof ssn !== 'string') return null;
  const last = ssn.slice(-4);
  return `***-**-${last}`;
}

// Secure seed on startup (creates hashed passwords)
async function ensureSeed() {
  try {
    await seedPatched();
  } catch (e) {
    console.error('Seed error:', e.message);
  }
}

// Secure login
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ message: 'Invalid input types' });
    }

    if (containsOperator(req.body)) return res.status(400).json({ message: 'Operators not allowed' });

    if (tooManyAttempts(username)) return res.status(429).json({ message: 'Too many login attempts' });

    const user = await User.findOne({ username: username.trim() });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    const token = signToken(user);
    // mask SSN in non-admin responses
    const responseUser = { id: user._id, username: user.username, role: user.role, fullName: user.fullName, ssn: maskSSN(user.ssn) };
    return res.json({ success: true, token, user: responseUser });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// Safe search: accept only simple string keywords (no JSON operators)
app.get('/search', async (req, res) => {
  try {
    const q = req.query.q;
    if (!q || typeof q !== 'string') return res.json([]);
    // reject JSON/object style inputs
    try { JSON.parse(q); return res.status(400).json({ message: 'Complex queries not allowed' }); } catch {}

    const safe = escapeRegExp(q);
    const regex = new RegExp(safe, 'i');
    const results = await User.find({ $or: [{ username: regex }, { fullName: regex }] });
    // mask SSN for non-admin callers
    const out = results.map(u => ({ username: u.username, fullName: u.fullName, role: u.role, ssn: maskSSN(u.ssn) }));
    return res.json(out);
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// Allow only role-based filter (no raw queries)
app.post('/users/filter', async (req, res) => {
  try {
    const filter = req.body || {};
    if (containsOperator(filter)) return res.status(400).json({ message: 'Operators not allowed' });
    const role = typeof filter.role === 'string' ? filter.role : null;
    const q = role ? { role } : {};
    const users = await User.find(q);
    const out = users.map(u => ({ username: u.username, fullName: u.fullName, role: u.role, ssn: maskSSN(u.ssn) }));
    return res.json({ count: out.length, users: out });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// Records search: only allow patientId string; admin can request all via /admin/export
app.post('/records/search', async (req, res) => {
  try {
    const q = req.body || {};
    if (containsOperator(q)) return res.status(400).json({ message: 'Operators not allowed' });
    const patientId = typeof q.patientId === 'string' ? q.patientId : null;
    if (!patientId) return res.status(400).json({ message: 'patientId required' });
    const regex = new RegExp(escapeRegExp(patientId), 'i');
    const records = await MedicalRecord.find({ patientId: regex });
    return res.json({ count: records.length, records });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// Admin export: strict role check and full data only for admins
app.post('/admin/export', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const users = await User.find({});
    const records = await MedicalRecord.find({});
    return res.json({ users, records });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// Admin query - disabled dynamic parsing; allow only role filter or ssn regex guarded
app.post('/admin/query', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const { role } = req.body || {};
    if (role && typeof role === 'string') {
      const results = await User.find({ role });
      return res.json(results);
    }
    return res.status(400).json({ message: 'Only simple admin filters allowed' });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

app.get('/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.sub);
    if (!user) return res.status(404).json({ message: 'User not found' });
    const out = { username: user.username, role: user.role, fullName: user.fullName, ssn: maskSSN(user.ssn) };
    return res.json(out);
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok', message: 'Patched secure server running' }));

async function setup() {
  await connect();
  await ensureSeed();
  const PORT = process.env.PORT || 4400;
  app.listen(PORT, '0.0.0.0', () => console.log(`Patched secure server running on http://0.0.0.0:${PORT}`));
}

setup().catch(err => { console.error(err); process.exit(1); });
