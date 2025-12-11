// server.js (sqlite3 version)
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Config uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, `${Date.now()}_${file.originalname}`),
});
const upload = multer({ storage });

// DB init (sqlite3)
const DB_PATH = path.join(__dirname, 'chamados.db');
const db = new sqlite3.Database(DB_PATH);

// Create tables if not exists
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    description TEXT,
    requester_id INTEGER,
    priority TEXT,
    status TEXT,
    assigned_to INTEGER,
    created_at TEXT,
    updated_at TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER,
    author_id INTEGER,
    author_name TEXT,
    text TEXT,
    attachment TEXT,
    date TEXT
  )`);
});

// Helpers
const SECRET = process.env.JWT_SECRET || 'trocar_este_seguro';
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT ? Number(process.env.EMAIL_PORT) : 587,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  const token = header.replace('Bearer ', '');
  try {
    const data = jwt.verify(token, SECRET);
    req.user = data;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Routes
app.post('/api/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email e senha obrigatórios' });
  const hash = await bcrypt.hash(password, 10);
  const stmt = db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)');
  stmt.run(name || '', email, hash, role || 'user', function(err) {
    if (err) return res.status(400).json({ error: 'Email já cadastrado' });
    const user = { id: this.lastID, name, email, role: role || 'user' };
    const token = jwt.sign(user, SECRET, { expiresIn: '7d' });
    res.json({ user, token });
  });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, row) => {
    if (err) return res.status(500).json({ error: 'Erro no servidor' });
    if (!row) return res.status(400).json({ error: 'Credenciais inválidas' });
    const ok = await bcrypt.compare(password, row.password);
    if (!ok) return res.status(400).json({ error: 'Credenciais inválidas' });
    const user = { id: row.id, name: row.name, email: row.email, role: row.role };
    const token = jwt.sign(user, SECRET, { expiresIn: '7d' });
    res.json({ user, token });
  });
});

// Create ticket (with optional attachment)
app.post('/api/tickets', authMiddleware, upload.single('attachment'), (req, res) => {
  const { title, description, priority } = req.body;
  const file = req.file ? `/uploads/${path.basename(req.file.path)}` : null;
  const now = new Date().toISOString();
  db.run('INSERT INTO tickets (title, description, requester_id, priority, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [title, description, req.user.id, priority || 'Média', 'Aberto', now, now],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      const ticketId = this.lastID;
      if (file) {
        db.run('INSERT INTO messages (ticket_id, author_id, author_name, text, attachment, date) VALUES (?, ?, ?, ?, ?, ?)',
          [ticketId, req.user.id, req.user.name, 'Anexo enviado', file, now]);
      }
      // Notify TI by email (optional)
      if (process.env.NOTIFY_EMAIL_TO) {
        transporter.sendMail({
          from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
          to: process.env.NOTIFY_EMAIL_TO,
          subject: `Novo chamado: ${title}`,
          text: `${req.user.name} abriu um chamado (Prioridade: ${priority || 'Média'})\n\n${description}`,
        }).catch(console.error);
      }
      res.json({ id: ticketId });
    });
});

// List tickets (TI sees all, users see own)
app.get('/api/tickets', authMiddleware, (req, res) => {
  if (req.user.role === 'ti') {
    db.all('SELECT * FROM tickets ORDER BY created_at DESC', [], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  } else {
    db.all('SELECT * FROM tickets WHERE requester_id = ? ORDER BY created_at DESC', [req.user.id], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  }
});

// Get single ticket with messages
app.get('/api/tickets/:id', authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  db.get('SELECT * FROM tickets WHERE id = ?', [id], (err, ticket) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!ticket) return res.status(404).json({ error: 'Chamado não encontrado' });
    if (req.user.role !== 'ti' && ticket.requester_id !== req.user.id) return res.status(403).json({ error: 'Acesso negado' });
    db.all('SELECT * FROM messages WHERE ticket_id = ? ORDER BY date ASC', [id], (err2, messages) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json({ ticket, messages });
    });
  });
});

// Post message (reply) (with optional attachment)
app.post('/api/tickets/:id/messages', authMiddleware, upload.single('attachment'), (req, res) => {
  const id = Number(req.params.id);
  const { text } = req.body;
  const file = req.file ? `/uploads/${path.basename(req.file.path)}` : null;
  const now = new Date().toISOString();
  db.run('INSERT INTO messages (ticket_id, author_id, author_name, text, attachment, date) VALUES (?, ?, ?, ?, ?, ?)',
    [id, req.user.id, req.user.name, text || (file ? 'Anexo' : ''), file, now],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      db.run('UPDATE tickets SET updated_at = ? WHERE id = ?', [now, id]);
      // Optional email notify the requester when TI replies
      db.get('SELECT * FROM tickets WHERE id = ?', [id], (err2, ticket) => {
        if (!err2 && ticket && req.user.role === 'ti') {
          db.get('SELECT * FROM users WHERE id = ?', [ticket.requester_id], (e3, requester) => {
            if (!e3 && requester && requester.email && process.env.EMAIL_USER) {
              transporter.sendMail({
                from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
                to: requester.email,
                subject: `Resposta ao seu chamado #${id} — ${ticket.title}`,
                text: `${req.user.name} respondeu: ${text || '[anexo]'}`,
              }).catch(console.error);
            }
          });
        }
      });
      res.json({ ok: true });
    });
});

// Change status / assign
app.post('/api/tickets/:id/update', authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  const { status, assignedTo } = req.body;
  const now = new Date().toISOString();
  if (status) {
    db.run('UPDATE tickets SET status = ?, updated_at = ? WHERE id = ?', [status, now, id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (assignedTo) {
        db.run('UPDATE tickets SET assigned_to = ?, updated_at = ? WHERE id = ?', [assignedTo, now, id], function(err2) {
          if (err2) return res.status(500).json({ error: err2.message });
          return res.json({ ok: true });
        });
      } else return res.json({ ok: true });
    });
  } else if (assignedTo) {
    db.run('UPDATE tickets SET assigned_to = ?, updated_at = ? WHERE id = ?', [assignedTo, now, id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      return res.json({ ok: true });
    });
  } else {
    res.json({ ok: true });
  }
});

// Basic users list (TI)
app.get('/api/users', authMiddleware, (req, res) => {
  if (req.user.role !== 'ti') return res.status(403).json({ error: 'Acesso negado' });
  db.all('SELECT id, name, email, role FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
