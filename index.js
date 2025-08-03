const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const { Connector } = require('@google-cloud/cloud-sql-connector');
const { Pool } = require('pg');
require('dotenv').config();

async function main() {
  const connector = new Connector();

  const clientOpts = await connector.getOptions({
    instanceConnectionName: process.env.INSTANCE_CONNECTION_NAME,
    authType: 'PASSWORD',
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
  });

  const pool = new Pool({
    ...clientOpts,
    database: process.env.DB_NAME,
  });

  const app = express();
  app.use(cors());
  app.use(express.json());
  const port = process.env.PORT || 8080;
  const SECRET = process.env.JWT_SECRET;


  pool.connect()
    .then(() => console.log("Connected to PostgreSQL database"))
    .catch((err) => console.error("Database connection error:", err));

  // --- SIGNUP ---
  app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    try {
      const existing = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      if (existing.rows.length > 0) {
        return res.status(400).json({ message: 'User already exists' });
      }
      const hashed = await bcrypt.hash(password, 10);
      await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashed]);
      const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
      res.json({ message: 'Signup successful', token, username });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error during signup' });
    }
  });

  // --- LOGIN ---
  app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
      const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
      const user = result.rows[0];
      if (!user) return res.status(400).json({ message: 'Invalid username or password' });
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(400).json({ message: 'Invalid username or password' });
      const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
      res.json({ token, username });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Login failed due to server error' });
    }
  });

  app.listen(port, () => console.log(`Server running on port ${port}`));
}

main();
