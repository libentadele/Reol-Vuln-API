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

// vulnerable login endpoint
app.post('/auth/login', async (req, res) => {
  try {
    // pass body directly to db
    const query = req.body;
    console.log('[VULN] Login query:', JSON.stringify(query));
    
    const user = await User.findOne(query);
    
    if (user) {
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
    }
    return res.status(401).json({ message: 'Invalid credentials' });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// vulnerable search endpoint
app.get('/search', async (req, res) => {
  try {
    const q = req.query.q;
    if (!q) return res.json([]);
    
    // parse json from query
    let queryObj;
    try {
      queryObj = JSON.parse(q);
    } catch (e) {
      // fallback to string search
      queryObj = { $or: [
        { username: { $regex: q, $options: 'i' } },
        { fullName: { $regex: q, $options: 'i' } },
        { ssn: { $regex: q, $options: 'i' } }
      ]};
    }
    
    console.log('[VULN] Search query:', JSON.stringify(queryObj));

    const results = await User.find(queryObj);
    return res.json(results);
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// vulnerable filter endpoint
app.post('/users/filter', async (req, res) => {
  try {
    // pass body to db query
    const filter = req.body;
    console.log('[VULN] User filter query:', JSON.stringify(filter));
    
    const users = await User.find(filter);
    return res.json({ count: users.length, users });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// vulnerable find endpoint
app.get('/users/find', async (req, res) => {
  try {
    const criteria = req.query.criteria;
    if (!criteria) {
      return res.status(400).json({ message: 'criteria parameter required' });
    }
    
    // parse json from param
    let queryObj;
    try {
      queryObj = JSON.parse(criteria);
    } catch (e) {
      return res.status(400).json({ message: 'Invalid JSON in criteria' });
    }
    
    console.log('[VULN] Find users query:', JSON.stringify(queryObj));
    
    const users = await User.find(queryObj);
    return res.json(users);
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// vulnerable records search
app.post('/records/search', async (req, res) => {
  try {
    // pass body directly
    const query = req.body;
    console.log('[VULN] Records search query:', JSON.stringify(query));
    
    const records = await MedicalRecord.find(query);
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
    // parse query string
    const { query } = req.body;
    if (!query) {
      return res.status(400).json({ message: 'Query required' });
    }
    
    const mq = JSON.parse(query);
    console.log('[VULN] Admin query:', JSON.stringify(mq));
    
    // use parsed query directly
    const results = await User.find(mq);
    return res.json(results);
  } catch (e) {
    return res.status(400).json({ message: e.message });
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
