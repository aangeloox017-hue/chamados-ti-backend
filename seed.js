// seed.js - cria usuário TI inicial (sqlite3)
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const db = new sqlite3.Database('./chamados.db');

async function run() {
  const hash = await bcrypt.hash('Senha123!', 10);
  db.run('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)', ['TI Admin', 'ti@escola.local', hash, 'ti'], function(err) {
    if (err) {
      console.log('Já existe usuário ou erro:', err.message);
    } else {
      console.log('Usuário TI criado: ti@escola.local / Senha123!');
    }
    process.exit(0);
  });
}
run();
