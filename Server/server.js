const express = require('express');
const path = require('path');
const cors = require('cors');
const db = require('./db');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // для доступа к MainHTML.html

app.post('/register', (req, res) => {
  const { username, subname, email, password } = req.body;

  if (!username || !subname || !email || !password) {
    return res.status(400).send('Все поля обязательны');
  }

  const sql = `
    INSERT INTO users (username, subname, email, password)
    VALUES (?, ?, ?, ?)
  `;

  db.query(sql, [username, subname, email, password || null], (err, result) => {
    if (err) {
      console.error('Ошибка при сохранении:', err);
      return res.status(500).send('Ошибка сервера');
    }

    res.send('Регистрация прошла успешно!');
  });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send('Email и пароль обязательны');
  }

  const sql = 'SELECT * FROM users WHERE email = ? AND password = ?';
  
  db.query(sql, [email, password], (err, results) => {
    if (err) {
      console.error('Ошибка при поиске пользователя:', err);
      return res.status(500).send('Ошибка сервера');
    }

    if (results.length === 0) {
      return res.status(401).send('Неверный email или пароль');
    }

    const user = results[0];
    res.send(`Добро пожаловать, ${user.username} ${user.subname}!`);
  });
});

const bcrypt = require('bcrypt');

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const sql = 'SELECT * FROM users WHERE email = ?';
  db.query(sql, [email], async (err, results) => {
    if (err) {
      return res.status(500).send('Ошибка сервера');
    }

    if (results.length === 0) {
      return res.status(401).send('Неверный email или пароль');
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    
    if (!match) {
      return res.status(401).send('Неверный email или пароль');
    }

    res.send(`Добро пожаловать, ${user.username}!`);
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен: http://localhost:${PORT}`);
});