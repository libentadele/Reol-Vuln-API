const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { connect } = require('./db');
const { User, MedicalRecord } = require('./models');
const { seedDatabase } = require('./seed');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'vulnerable-jwt-secret';

// make jwt token
function signToken(user) {
  return jwt.sign(
    { sub: user._id, role: user.role, username: user.username },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
}

// check if token valid
function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) {
    return res.status(401).json({ message: 'Missing authorization header' });
  }
  
  const token = auth.replace('Bearer ', '');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// check user role
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: `Access denied. Required roles: ${roles.join(', ')}` });
    }
    next();
  };
}

const bcrypt = require('bcryptjs');

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

// secure login endpoint
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};

    // basic type checks
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ message: 'Invalid input types' });
    }

    // reject operator-style payloads
    if (containsOperator(req.body)) {
      return res.status(400).json({ message: 'Operators not allowed in login' });
    }

    // explicit query - never pass raw body
    const user = await User.findOne({ username: username.trim() });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    // compare hashed password (seed uses hashed passwords)
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    const token = signToken(user);
    return res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        fullName: user.fullName
      }
    });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// vulnerable search endpoint
app.get('/search', async (req, res) => {
  try {
    const q = req.query.q;
    if (!q) return res.json([]);

    // disallow JSON/object-style queries coming from client
    try {
      const parsed = JSON.parse(q);
      if (typeof parsed === 'object') {
        return res.status(400).json({ message: 'Complex queries not allowed' });
      }
    } catch (e) {
      // not JSON — proceed as a simple keyword
    }

    // escape user input for safe regex
    const safe = String(q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(safe, 'i');
    const results = await User.find({ $or: [ { username: regex }, { fullName: regex } ] });

    // mask SSN in search results
    const out = results.map(u => ({ id: u._id, username: u.username, fullName: u.fullName, role: u.role, ssn: u.ssn ? '***-**-' + String(u.ssn).slice(-4) : null }));
    return res.json(out);
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// vulnerable filter endpoint
app.post('/users/filter', async (req, res) => {
  try {
    const filter = req.body || {};
    if (containsOperator(filter)) return res.status(400).json({ message: 'Operators not allowed' });
    // allow only role filter or empty
    const role = typeof filter.role === 'string' ? filter.role : null;
    const q = role ? { role } : {};
    const users = await User.find(q);
    const out = users.map(u => ({ id: u._id, username: u.username, fullName: u.fullName, role: u.role, ssn: u.ssn ? '***-**-' + String(u.ssn).slice(-4) : null }));
    return res.json({ count: out.length, users: out });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// vulnerable find endpoint
app.get('/users/find', async (req, res) => {
  try {
    const criteria = req.query.criteria;
    if (!criteria) return res.status(400).json({ message: 'criteria parameter required' });
    // only allow simple field=value pairs (no operators)
    let parsed;
    try { parsed = JSON.parse(criteria); } catch (e) { return res.status(400).json({ message: 'Invalid JSON in criteria' }); }
    if (containsOperator(parsed)) return res.status(400).json({ message: 'Operators not allowed' });
    // only allow role or username filters
    const q = {};
    if (typeof parsed.role === 'string') q.role = parsed.role;
    if (typeof parsed.username === 'string') q.username = parsed.username;
    const users = await User.find(q);
    const out = users.map(u => ({ id: u._id, username: u.username, role: u.role, fullName: u.fullName }));
    return res.json(out);
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// vulnerable records search
app.post('/records/search', async (req, res) => {
  try {
    const q = req.body || {};
    if (containsOperator(q)) return res.status(400).json({ message: 'Operators not allowed' });
    const patientId = typeof q.patientId === 'string' ? q.patientId : null;
    if (!patientId) return res.status(400).json({ message: 'patientId required' });
    const safe = String(patientId).replace(/[.*+?^${}()|[\\]\\]/g, '\\$&');
    const regex = new RegExp(safe, 'i');
    const records = await MedicalRecord.find({ patientId: regex });
    return res.json({ count: records.length, records });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// admin export endpoint
app.post('/admin/export', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    // get all data
    const users = await User.find({});
    const records = await MedicalRecord.find({});
    return res.json({ users, records });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// vulnerable admin query
app.post('/admin/query', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    // allow only safe admin filters (e.g., role)
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

// vulnerable admin users
app.post('/admin/users', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    // pass filter to db
    const filter = req.body.filter || {};
    console.log('[VULN] Admin users filter:', JSON.stringify(filter));
    
    const users = await User.find(filter);
    return res.json({ count: users.length, users });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// doctor patients endpoint
app.get('/doctor/patients', verifyToken, requireRole('doctor', 'admin'), async (req, res) => {
  try {
    const patients = await User.find({ role: 'patient' });
    const records = await MedicalRecord.find({});
    return res.json({ patients, records });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'Vulnerable server is running' });
});

// get current user
app.get('/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.sub);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    return res.json({
      id: user._id,
      username: user.username,
      role: user.role,
      fullName: user.fullName
    });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

async function setup() {
  // connect to mongodb
  await connect();
  
  // seed test data
  await seedDatabase();

  const PORT = process.env.PORT || 4000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Vulnerable server running on http://0.0.0.0:${PORT}`);
    console.log('\nVulnerable Endpoints:');
    console.log('  POST /auth/login - NoSQL injection in authentication');
    console.log('  GET  /search - NoSQL injection in search');
    console.log('  POST /users/filter - NoSQL injection in user filtering');
    console.log('  GET  /users/find - NoSQL injection in user find');
    console.log('  POST /records/search - NoSQL injection in records search');
    console.log('  POST /admin/query - NoSQL injection in admin queries');
    console.log('  POST /admin/users - NoSQL injection in admin user listing');
  });
}

setup().catch(error => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
