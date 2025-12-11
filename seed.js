// seed.js - cria usuário TI inicial
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require('bcrypt');
const db = new sqlite3.Database("./chamados.db");
async function run() {
  const hash = await bcrypt.hash('Senha123!', 10);
  try {
    db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)').run('TI Admin', 'ti@escola.local', hash, 'ti');
    console.log('Usuário TI criado: ti@escola.local / Senha123!');
  } catch (e) {
    console.log('Já existe usuário ou erro:', e.message);
  }
  process.exit(0);
}
run();
