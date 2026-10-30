
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const path = require("path");

const app = express();
const db = new Database("database/inventory.db");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'operator'
);

CREATE TABLE IF NOT EXISTS models (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  brand TEXT NOT NULL,
  name TEXT NOT NULL,
  UNIQUE(brand, name)
);

CREATE TABLE IF NOT EXISTS phones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  inventory_number TEXT UNIQUE NOT NULL,
  model_id INTEGER NOT NULL,
  imei TEXT UNIQUE,
  serial_number TEXT,
  storage TEXT,
  color TEXT,
  condition TEXT DEFAULT 'Por verificar',
  status TEXT DEFAULT 'Disponível',
  location TEXT,
  responsible TEXT,
  acquisition_date TEXT,
  acquisition_value REAL,
  FOREIGN KEY(model_id) REFERENCES models(id)
);
`);

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json());

if (!process.env.SESSION_SECRET) {
  throw new Error("Defina SESSION_SECRET no ficheiro .env");
}

app.use(session({
  store: new SQLiteStore({
    db: "sessions.db",
    dir: "./database"
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

// Catálogo de 50 modelos

const catalog = {
  Apple: [
    "iPhone 16", "iPhone 16 Plus",
    "iPhone 16 Pro", "iPhone 16 Pro Max",
    "iPhone 15", "iPhone 15 Plus",
    "iPhone 15 Pro", "iPhone 15 Pro Max",
    "iPhone 14", "iPhone SE (3.ª geração)"
  ],
  Samsung: [
    "Galaxy S25", "Galaxy S25+",
    "Galaxy S25 Ultra", "Galaxy S24",
    "Galaxy S24+", "Galaxy S24 Ultra",
    "Galaxy A56", "Galaxy A36",
    "Galaxy A26", "Galaxy Z Flip6"
  ],
  Xiaomi: [
    "Xiaomi 15", "Xiaomi 15 Ultra",
    "Xiaomi 14", "Xiaomi 14 Ultra",
    "Redmi Note 14", "Redmi Note 14 Pro",
    "Redmi Note 14 Pro+", "Redmi 14C",
    "POCO X7", "POCO X7 Pro"
  ],
  Motorola: [
    "Edge 50 Neo", "Edge 50 Fusion",
    "Edge 50 Pro", "Razr 50",
    "Razr 50 Ultra", "Moto G85",
    "Moto G55", "Moto G35",
    "Moto G75", "Edge 60 Pro"
  ],
  Huawei: [
    "Pura 70", "Pura 70 Pro",
    "Pura 70 Ultra", "Mate 60 Pro",
    "Mate X6", "nova 13",
    "nova 13 Pro", "nova 12 SE",
    "P60 Pro", "Mate 50 Pro"
  ]
};

const insertModel = db.prepare(
  "INSERT OR IGNORE INTO models (brand, name) VALUES (?, ?)"
);

const seed = db.transaction(() => {
  for (const [brand, models] of Object.entries(catalog)) {
    for (const model of models) {
      insertModel.run(brand, model);
    }
  }
});

seed();

// Autenticação

function auth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Autenticação necessária"
    });
  }
  next();
}

function admin(req, res, next) {
  if (req.session.user?.role !== "admin") {
    return res.status(403).json({
      error: "Acesso reservado ao administrador"
    });
  }
  next();
}

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      error: "Preencha os campos de acesso"
    });
  }

  const user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({
      error: "Credenciais inválidas"
    });
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Erro de sessão" });

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role
    };

    res.json({ success: true, user: req.session.user });
  });
});

app.post("/api/logout", auth, (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// Criar utilizadores: apenas administrador

app.post("/api/users", auth, admin, async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || password.length < 12 ||
      !["admin", "operator"].includes(role)) {
    return res.status(400).json({
      error: "Dados inválidos. Palavra-passe mínima de 12 caracteres."
    });
  }

  try {
    const hash = await bcrypt.hash(password, 12);

    db.prepare(`
      INSERT INTO users (username, password, role)
      VALUES (?, ?, ?)
    `).run(username, hash, role);

    res.status(201).json({ success: true });
  } catch {
    res.status(400).json({
      error: "Utilizador já existente ou dados inválidos"
    });
  }
});

// Consultar modelos

app.get("/api/models", auth, (req, res) => {
  res.json(db.prepare(
    "SELECT * FROM models ORDER BY brand, name"
  ).all());
});

// Consultar inventário

app.get("/api/phones", auth, (req, res) => {
  const phones = db.prepare(`
    SELECT phones.*, models.brand, models.name AS model
    FROM phones
    JOIN models ON phones.model_id = models.id
    ORDER BY phones.inventory_number
  `).all();

  res.json(phones);
});

// Registar telemóvel

app.post("/api/phones", auth, (req, res) => {
  const {
    inventory_number, model_id, imei, serial_number,
    storage, color, condition, status, location,
    responsible, acquisition_date, acquisition_value
  } = req.body;

  if (!inventory_number || !model_id) {
    return res.status(400).json({
      error: "Número de inventário e modelo são obrigatórios"
    });
  }

  try {
    const result = db.prepare(`
      INSERT INTO phones (
        inventory_number, model_id, imei, serial_number,
        storage, color, condition, status, location,
        responsible, acquisition_date, acquisition_value
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      inventory_number, model_id, imei || null,
      serial_number || null, storage || null,
      color || null, condition || "Por verificar",
      status || "Disponível", location || null,
      responsible || null, acquisition_date || null,
      acquisition_value ?? null
    );

    res.status(201).json({
      success: true,
      id: result.lastInsertRowid
    });
  } catch {
    res.status(400).json({
      error: "Registo duplicado ou dados inválidos"
    });
  }
});

// Estatísticas

app.get("/api/dashboard", auth, (req, res) => {
  const total = db.prepare(
    "SELECT COUNT(*) AS total FROM phones"
  ).get().total;

  const byBrand = db.prepare(`
    SELECT models.brand, COUNT(*) AS total
    FROM phones
    JOIN models ON phones.model_id = models.id
    GROUP BY models.brand
  `).all();

  const byStatus = db.prepare(`
    SELECT status, COUNT(*) AS total
    FROM phones GROUP BY status
  `).all();

  res.json({ total, byBrand, byStatus });
});

app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`MobileInventory ativo na porta ${PORT}`);
});
  