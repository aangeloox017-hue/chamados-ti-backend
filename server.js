// -------------------------------
// SERVER.JS — VERSÃO CORRIGIDA
// Compatível com Render.com
// Usa sqlite3 (não better-sqlite3)
// -------------------------------

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const nodemailer = require("nodemailer");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ------------------------------
// ROTAS DE TESTE
// ------------------------------
app.get("/api/status", (req, res) => {
  res.json({ status: "ok", message: "API está online 🚀" });
});

// ------------------------------
// UPLOAD DE ARQUIVOS
// ------------------------------
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) =>
    cb(null, `${Date.now()}_${file.originalname}`),
});
const upload = multer({ storage });

// ------------------------------
// BANCO DE DADOS SQLITE
// ------------------------------
const db = new sqlite3.Database("./chamados.db");

// Criação das tabelas
db.serialize
