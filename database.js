const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const DB_PATH = path.join(__dirname, 'data', 'vm-system.db');

let db = null;
let SQL = null;

// Save database to disk
function saveDb() {
  if (!db) return;
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// Auto-save every 30 seconds
setInterval(() => { if (db) saveDb(); }, 30000);

async function initDb() {
  if (db) return db;

  // Ensure data directories exist
  const dataDir = path.join(__dirname, 'data');
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
  const photosDir = path.join(__dirname, 'data', 'photos');
  if (!fs.existsSync(photosDir)) fs.mkdirSync(photosDir, { recursive: true });

  SQL = await initSqlJs();

  // Load existing database or create new one
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.run('PRAGMA foreign_keys = ON');
  initializeSchema();
  return db;
}

function getDb() {
  if (!db) throw new Error('Database not initialized. Call initDb() first.');
  return db;
}

function initializeSchema() {
  db.run(`
    CREATE TABLE IF NOT EXISTS locations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS people (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL CHECK(type IN ('employee', 'visitor')),
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      company TEXT,
      email TEXT,
      phone TEXT,
      photo_path TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'fire_marshal')),
      full_name TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS visits (
      id TEXT PRIMARY KEY,
      person_id TEXT NOT NULL REFERENCES people(id),
      location_id TEXT NOT NULL REFERENCES locations(id),
      check_in TEXT DEFAULT (datetime('now')),
      check_out TEXT,
      host TEXT,
      purpose TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT DEFAULT (datetime('now')),
      action TEXT NOT NULL,
      person_id TEXT,
      location_id TEXT,
      visit_id TEXT,
      user_id TEXT,
      details TEXT
    )
  `);

  // Indexes
  db.run('CREATE INDEX IF NOT EXISTS idx_visits_person ON visits(person_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_visits_location ON visits(location_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_visits_checkin ON visits(check_in)');
  db.run('CREATE INDEX IF NOT EXISTS idx_visits_checkout ON visits(check_out)');
  db.run('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)');
  db.run('CREATE INDEX IF NOT EXISTS idx_people_name ON people(first_name, last_name)');

  // Seed locations
  const stmt = db.prepare('INSERT OR IGNORE INTO locations (id, name) VALUES (?, ?)');
  stmt.run(['leeds', 'Leeds']);
  stmt.run(['axcess-10', 'Axcess-10']);
  stmt.run(['crawley', 'Crawley']);
  stmt.free();

  // Seed default admin if none exists
  const result = db.exec("SELECT COUNT(*) as count FROM users WHERE role = 'admin'");
  const adminCount = result[0]?.values[0]?.[0] || 0;
  if (adminCount === 0) {
    const hash = bcrypt.hashSync('admin123', 10);
    db.run('INSERT INTO users (id, username, password_hash, role, full_name) VALUES (?, ?, ?, ?, ?)',
      [uuidv4(), 'admin', hash, 'admin', 'System Administrator']);
    console.log('Default admin created — username: admin, password: admin123');
  }

  saveDb();
}

// Helper: run a query and return array of objects
function queryAll(sql, params = []) {
  const stmt = db.prepare(sql);
  if (params.length) stmt.bind(params);
  const rows = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}

// Helper: run a query and return first row as object
function queryGet(sql, params = []) {
  const rows = queryAll(sql, params);
  return rows[0] || null;
}

// Helper: run an insert/update/delete
function runSql(sql, params = []) {
  db.run(sql, params);
  saveDb();
}

module.exports = { initDb, getDb, queryAll, queryGet, runSql, saveDb };
