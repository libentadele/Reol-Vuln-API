const express = require('express');
const bodyParser = require('body-parser');
const { connect } = require('../src/db');
const { User, MedicalRecord } = require('../src/models');

const app = express();
app.use(bodyParser.json());

// simple helper: reject any object containing keys starting with $
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

// login with explicit query and input validation
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ message: 'Invalid input types' });
    }

    // explicit match - do not pass objects directly
    const user = await User.findOne({ username: username.trim(), password });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    return res.json({ success: true, user: { username: user.username, role: user.role } });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// safe search: only allow simple string q values
app.get('/search', async (req, res) => {
  try {
    const q = req.query.q;
    if (!q) return res.json([]);

    // reject if the client sent JSON/operators
    let parsed;
    try {
      parsed = JSON.parse(q);
      // if parsed is object, disallow
      if (typeof parsed === 'object') {
        return res.status(400).json({ message: 'Complex queries not allowed' });
      }
    } catch (e) {
      // q is simple string, proceed
    }

    const regex = new RegExp(String(q), 'i');
    const results = await User.find({ $or: [{ username: regex }, { fullName: regex }, { ssn: regex }] });
    return res.json(results);
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

// protected admin export is unchanged here but kept for completeness
app.post('/admin/export', async (req, res) => {
  try {
    // in this minimal patched example we do not implement JWT here
    return res.status(403).json({ message: 'Admin endpoint protected in full deployment' });
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

app.get('/health', (req, res) => res.json({ status: 'ok', message: 'Patched server running' }));

async function setup() {
  await connect();
  const PORT = process.env.PORT || 4400;
  app.listen(PORT, '0.0.0.0', () => console.log(`Patched server running on http://0.0.0.0:${PORT}`));
}

setup().catch(err => { console.error(err); process.exit(1); });
