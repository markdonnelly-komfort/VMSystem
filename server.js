const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { initDb, queryAll, queryGet, runSql, saveDb } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'vm-system-secret-change-in-production';

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/photos', express.static(path.join(__dirname, 'data', 'photos')));

// Auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

function logAction(action, { personId, locationId, visitId, userId, details } = {}) {
  runSql(`INSERT INTO audit_log (action, person_id, location_id, visit_id, user_id, details) VALUES (?, ?, ?, ?, ?, ?)`,
    [action, personId || null, locationId || null, visitId || null, userId || null, details || null]);
}

// ── AUTH ──
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const user = queryGet('SELECT * FROM users WHERE username = ?', [username]);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role, fullName: user.full_name }, JWT_SECRET, { expiresIn: '12h' });
  logAction('admin_login', { userId: user.id, details: `${user.full_name} logged in` });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, fullName: user.full_name } });
});

// ── LOCATIONS ──
app.get('/api/locations', (req, res) => {
  res.json(queryAll('SELECT * FROM locations ORDER BY name'));
});

// ── PEOPLE ──
app.get('/api/people/search', (req, res) => {
  const { q, type } = req.query;
  let sql = "SELECT * FROM people WHERE (first_name || ' ' || last_name) LIKE ?";
  const params = [`%${q || ''}%`];
  if (type) { sql += ' AND type = ?'; params.push(type); }
  sql += ' ORDER BY last_name, first_name LIMIT 20';
  res.json(queryAll(sql, params));
});

app.get('/api/people/:id', (req, res) => {
  const person = queryGet('SELECT * FROM people WHERE id = ?', [req.params.id]);
  if (!person) return res.status(404).json({ error: 'Person not found' });
  res.json(person);
});

app.post('/api/people', (req, res) => {
  const { type, firstName, lastName, company, email, phone } = req.body;
  if (!type || !firstName || !lastName) {
    return res.status(400).json({ error: 'Type, first name, and last name are required' });
  }
  const id = uuidv4();
  runSql('INSERT INTO people (id, type, first_name, last_name, company, email, phone) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [id, type, firstName, lastName, company || null, email || null, phone || null]);
  logAction('person_registered', { personId: id, details: `${type}: ${firstName} ${lastName}` });
  res.status(201).json(queryGet('SELECT * FROM people WHERE id = ?', [id]));
});

app.post('/api/people/:id/photo', (req, res) => {
  const { photo } = req.body;
  if (!photo) return res.status(400).json({ error: 'Photo data required' });

  const person = queryGet('SELECT * FROM people WHERE id = ?', [req.params.id]);
  if (!person) return res.status(404).json({ error: 'Person not found' });

  const fs = require('fs');
  const matches = photo.match(/^data:image\/(\w+);base64,(.+)$/);
  if (!matches) return res.status(400).json({ error: 'Invalid photo format' });

  const ext = matches[1];
  const data = Buffer.from(matches[2], 'base64');
  const filename = `${uuidv4()}.${ext}`;
  fs.writeFileSync(path.join(__dirname, 'data', 'photos', filename), data);

  if (person.photo_path) {
    const oldPath = path.join(__dirname, 'data', 'photos', person.photo_path);
    if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
  }

  runSql("UPDATE people SET photo_path = ?, updated_at = datetime('now') WHERE id = ?", [filename, req.params.id]);
  logAction('photo_updated', { personId: req.params.id, details: `Photo updated for ${person.first_name} ${person.last_name}` });
  res.json({ photo_path: filename });
});

app.delete('/api/people/:id', authenticateToken, requireRole('admin'), (req, res) => {
  const person = queryGet('SELECT * FROM people WHERE id = ?', [req.params.id]);
  if (!person) return res.status(404).json({ error: 'Person not found' });

  runSql("UPDATE visits SET check_out = datetime('now') WHERE person_id = ? AND check_out IS NULL", [req.params.id]);
  runSql('DELETE FROM people WHERE id = ?', [req.params.id]);
  logAction('person_deleted', { personId: req.params.id, userId: req.user.id, details: `Deleted ${person.type}: ${person.first_name} ${person.last_name}` });
  res.json({ message: 'Person removed' });
});

// ── VISITS ──
app.post('/api/visits/checkin', (req, res) => {
  const { personId, locationId, host, purpose } = req.body;
  if (!personId || !locationId) return res.status(400).json({ error: 'Person and location are required' });

  const existing = queryGet('SELECT * FROM visits WHERE person_id = ? AND location_id = ? AND check_out IS NULL', [personId, locationId]);
  if (existing) return res.status(409).json({ error: 'Already checked in at this location', visit: existing });

  const id = uuidv4();
  runSql('INSERT INTO visits (id, person_id, location_id, host, purpose) VALUES (?, ?, ?, ?, ?)',
    [id, personId, locationId, host || null, purpose || null]);
  const person = queryGet('SELECT * FROM people WHERE id = ?', [personId]);
  logAction('check_in', { personId, locationId, visitId: id, details: `${person.first_name} ${person.last_name} checked in` });
  res.status(201).json(queryGet('SELECT * FROM visits WHERE id = ?', [id]));
});

app.post('/api/visits/checkout', (req, res) => {
  const { personId, locationId } = req.body;
  const visit = queryGet('SELECT * FROM visits WHERE person_id = ? AND location_id = ? AND check_out IS NULL', [personId, locationId]);
  if (!visit) return res.status(404).json({ error: 'No active visit found' });

  runSql("UPDATE visits SET check_out = datetime('now') WHERE id = ?", [visit.id]);
  const person = queryGet('SELECT * FROM people WHERE id = ?', [personId]);
  logAction('check_out', { personId, locationId, visitId: visit.id, details: `${person.first_name} ${person.last_name} checked out` });
  res.json(queryGet('SELECT * FROM visits WHERE id = ?', [visit.id]));
});

app.get('/api/visits/current/:locationId', (req, res) => {
  res.json(queryAll(`
    SELECT v.id as visit_id, v.check_in, v.host, v.purpose,
           p.id as person_id, p.type, p.first_name, p.last_name, p.company, p.photo_path
    FROM visits v JOIN people p ON v.person_id = p.id
    WHERE v.location_id = ? AND v.check_out IS NULL
    ORDER BY v.check_in DESC`, [req.params.locationId]));
});

app.get('/api/visits/current', authenticateToken, requireRole('admin', 'fire_marshal'), (req, res) => {
  res.json(queryAll(`
    SELECT v.id as visit_id, v.check_in, v.host, v.purpose,
           p.id as person_id, p.type, p.first_name, p.last_name, p.company, p.photo_path,
           l.id as location_id, l.name as location_name
    FROM visits v
    JOIN people p ON v.person_id = p.id
    JOIN locations l ON v.location_id = l.id
    WHERE v.check_out IS NULL
    ORDER BY l.name, p.last_name, p.first_name`));
});

// ── ADMIN ──
app.get('/api/admin/people', authenticateToken, requireRole('admin'), (req, res) => {
  const { type, q } = req.query;
  let sql = 'SELECT * FROM people WHERE 1=1';
  const params = [];
  if (type) { sql += ' AND type = ?'; params.push(type); }
  if (q) { sql += " AND (first_name || ' ' || last_name) LIKE ?"; params.push(`%${q}%`); }
  sql += ' ORDER BY last_name, first_name';
  res.json(queryAll(sql, params));
});

app.get('/api/admin/logs', authenticateToken, requireRole('admin'), (req, res) => {
  const { limit = 100, offset = 0, locationId, personId, action } = req.query;
  let sql = `SELECT al.*, p.first_name, p.last_name, l.name as location_name
    FROM audit_log al LEFT JOIN people p ON al.person_id = p.id LEFT JOIN locations l ON al.location_id = l.id WHERE 1=1`;
  const params = [];
  if (locationId) { sql += ' AND al.location_id = ?'; params.push(locationId); }
  if (personId) { sql += ' AND al.person_id = ?'; params.push(personId); }
  if (action) { sql += ' AND al.action = ?'; params.push(action); }
  sql += ' ORDER BY al.timestamp DESC LIMIT ? OFFSET ?';
  params.push(Number(limit), Number(offset));
  res.json(queryAll(sql, params));
});

app.get('/api/admin/visits', authenticateToken, requireRole('admin'), (req, res) => {
  const { locationId, from, to, limit = 100, offset = 0 } = req.query;
  let sql = `SELECT v.*, p.first_name, p.last_name, p.type, p.company, p.photo_path, l.name as location_name
    FROM visits v JOIN people p ON v.person_id = p.id JOIN locations l ON v.location_id = l.id WHERE 1=1`;
  const params = [];
  if (locationId) { sql += ' AND v.location_id = ?'; params.push(locationId); }
  if (from) { sql += ' AND v.check_in >= ?'; params.push(from); }
  if (to) { sql += ' AND v.check_in <= ?'; params.push(to); }
  sql += ' ORDER BY v.check_in DESC LIMIT ? OFFSET ?';
  params.push(Number(limit), Number(offset));
  res.json(queryAll(sql, params));
});

app.get('/api/admin/users', authenticateToken, requireRole('admin'), (req, res) => {
  res.json(queryAll('SELECT id, username, role, full_name, created_at FROM users ORDER BY role, full_name'));
});

app.post('/api/admin/users', authenticateToken, requireRole('admin'), (req, res) => {
  const { username, password, role, fullName } = req.body;
  if (!username || !password || !role || !fullName) return res.status(400).json({ error: 'All fields are required' });
  if (!['admin', 'fire_marshal'].includes(role)) return res.status(400).json({ error: 'Role must be admin or fire_marshal' });

  const existing = queryGet('SELECT id FROM users WHERE username = ?', [username]);
  if (existing) return res.status(409).json({ error: 'Username already exists' });

  const id = uuidv4();
  const hash = bcrypt.hashSync(password, 10);
  runSql('INSERT INTO users (id, username, password_hash, role, full_name) VALUES (?, ?, ?, ?, ?)', [id, username, hash, role, fullName]);
  logAction('user_created', { userId: req.user.id, details: `Created ${role}: ${fullName} (${username})` });
  res.status(201).json({ id, username, role, fullName });
});

app.delete('/api/admin/users/:id', authenticateToken, requireRole('admin'), (req, res) => {
  const user = queryGet('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });

  runSql('DELETE FROM users WHERE id = ?', [req.params.id]);
  logAction('user_deleted', { userId: req.user.id, details: `Deleted ${user.role}: ${user.full_name}` });
  res.json({ message: 'User removed' });
});

// ── FIRE MARSHAL ──
app.get('/api/fire/summary', authenticateToken, requireRole('admin', 'fire_marshal'), (req, res) => {
  res.json(queryAll(`
    SELECT l.id, l.name,
           COUNT(v.id) as total,
           SUM(CASE WHEN p.type = 'employee' THEN 1 ELSE 0 END) as employees,
           SUM(CASE WHEN p.type = 'visitor' THEN 1 ELSE 0 END) as visitors
    FROM locations l
    LEFT JOIN visits v ON v.location_id = l.id AND v.check_out IS NULL
    LEFT JOIN people p ON v.person_id = p.id
    GROUP BY l.id, l.name
    ORDER BY l.name`));
});

// SPA fallback
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server (async because sql.js init is async)
(async () => {
  await initDb();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`VM System running on http://0.0.0.0:${PORT}`);
  });
})();
