// server.js
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
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

// DB init
const db = new Database('chamados.db');

// Create tables if not exists
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT UNIQUE,
  password TEXT,
  role TEXT
);
CREATE TABLE IF NOT EXISTS tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT,
  description TEXT,
  requester_id INTEGER,
  priority TEXT,
  status TEXT,
  assigned_to INTEGER,
  created_at TEXT,
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_id INTEGER,
  author_id INTEGER,
  author_name TEXT,
  text TEXT,
  attachment TEXT,
  date TEXT
);
`);

// Helpers
const SECRET = process.env.JWT_SECRET || 'trocar_este_seguro';
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
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
  try {
    const stmt = db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)');
    const info = stmt.run(name || '', email, hash, role || 'user');
    const user = { id: info.lastInsertRowid, name, email, role: role || 'user' };
    const token = jwt.sign(user, SECRET, { expiresIn: '7d' });
    res.json({ user, token });
  } catch (err) {
    res.status(400).json({ error: 'Email já cadastrado' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!row) return res.status(400).json({ error: 'Credenciais inválidas' });
  const ok = await bcrypt.compare(password, row.password);
  if (!ok) return res.status(400).json({ error: 'Credenciais inválidas' });
  const user = { id: row.id, name: row.name, email: row.email, role: row.role };
  const token = jwt.sign(user, SECRET, { expiresIn: '7d' });
  res.json({ user, token });
});

// Create ticket (with optional attachment)
app.post('/api/tickets', authMiddleware, upload.single('attachment'), (req, res) => {
  const { title, description, priority } = req.body;
  const file = req.file ? `/uploads/${path.basename(req.file.path)}` : null;
  const now = new Date().toISOString();
  const stmt = db.prepare('INSERT INTO tickets (title, description, requester_id, priority, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)');
  const info = stmt.run(title, description, req.user.id, priority || 'Média', 'Aberto', now, now);
  const ticketId = info.lastInsertRowid;
  if (file) {
    const mstmt = db.prepare('INSERT INTO messages (ticket_id, author_id, author_name, text, attachment, date) VALUES (?, ?, ?, ?, ?, ?)');
    mstmt.run(ticketId, req.user.id, req.user.name, 'Anexo enviado', file, now);
  }

  // Notify TI by email (optional)
  if (process.env.NOTIFY_EMAIL_TO) {
    transporter.sendMail({
      from: process.env.SMTP_FROM,
      to: process.env.NOTIFY_EMAIL_TO,
      subject: `Novo chamado: ${title}`,
      text: `${req.user.name} abriu um chamado (Prioridade: ${priority || 'Média'})\n\n${description}`,
    }).catch(console.error);
  }

  res.json({ id: ticketId });
});

// List tickets (TI sees all, users see own)
app.get('/api/tickets', authMiddleware, (req, res) => {
  if (req.user.role === 'ti') {
    const rows = db.prepare('SELECT * FROM tickets ORDER BY created_at DESC').all();
    res.json(rows);
  } else {
    const rows = db.prepare('SELECT * FROM tickets WHERE requester_id = ? ORDER BY created_at DESC').all(req.user.id);
    res.json(rows);
  }
});

// Get single ticket with messages
app.get('/api/tickets/:id', authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(id);
  if (!ticket) return res.status(404).json({ error: 'Chamado não encontrado' });
  if (req.user.role !== 'ti' && ticket.requester_id !== req.user.id) return res.status(403).json({ error: 'Acesso negado' });
  const messages = db.prepare('SELECT * FROM messages WHERE ticket_id = ? ORDER BY date ASC').all(id);
  res.json({ ticket, messages });
});

// Post message (reply) (with optional attachment)
app.post('/api/tickets/:id/messages', authMiddleware, upload.single('attachment'), (req, res) => {
  const id = Number(req.params.id);
  const { text } = req.body;
  const file = req.file ? `/uploads/${path.basename(req.file.path)}` : null;
  const now = new Date().toISOString();
  const user = req.user;
  const stmt = db.prepare('INSERT INTO messages (ticket_id, author_id, author_name, text, attachment, date) VALUES (?, ?, ?, ?, ?, ?)');
  stmt.run(id, user.id, user.name, text || (file ? 'Anexo' : ''), file, now);
  db.prepare('UPDATE tickets SET updated_at = ? WHERE id = ?').run(now, id);

  // Optional email notify the requester when TI replies
  const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(id);
  if (user.role === 'ti' && ticket) {
    const requester = db.prepare('SELECT * FROM users WHERE id = ?').get(ticket.requester_id);
    if (requester && requester.email && process.env.SMTP_USER) {
      transporter.sendMail({
        from: process.env.SMTP_FROM,
        to: requester.email,
        subject: `Resposta ao seu chamado #${id} — ${ticket.title}`,
        text: `${user.name} respondeu: ${text || '[anexo]'}`,
      }).catch(console.error);
    }
  }

  res.json({ ok: true });
});

// Change status / assign
app.post('/api/tickets/:id/update', authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  const { status, assignedTo } = req.body;
  const now = new Date().toISOString();
  if (status) db.prepare('UPDATE tickets SET status = ?, updated_at = ? WHERE id = ?').run(status, now, id);
  if (assignedTo) db.prepare('UPDATE tickets SET assigned_to = ?, updated_at = ? WHERE id = ?').run(assignedTo, now, id);
  res.json({ ok: true });
});

// Basic users list (TI)
app.get('/api/users', authMiddleware, (req, res) => {
  if (req.user.role !== 'ti') return res.status(403).json({ error: 'Acesso negado' });
  const rows = db.prepare('SELECT id, name, email, role FROM users').all();
  res.json(rows);
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
