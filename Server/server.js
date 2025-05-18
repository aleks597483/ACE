const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const db = require('./db');
const mysql = require('mysql2/promise');
// Инициализация приложения
require('dotenv').config();

async function createDbConnection() {
  return await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'my_database',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });
}

// Проверка обязательных переменных окружения
if (!process.env.JWT_SECRET) {
  console.error('FATAL ERROR: JWT_SECRET is not defined');
  process.exit(1);
}

const SECRET_KEY = process.env.JWT_SECRET;
const app = express();
const PORT = process.env.PORT || 3000;

// Настройка CORS
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5500'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ==================== JWT Middleware ====================
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({ error: 'Требуется авторизация' });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Ошибка верификации токена:', err.message);
    return res.status(403).json({ error: 'Недействительный токен' });
  }
};

// ==================== Роуты ====================

// Проверка здоровья сервера
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date() });
});

// Регистрация
app.post('/register', async (req, res) => {
  try {
    const { username, subname, email, password } = req.body;

    // Валидация
    if (!username || !subname || !email || !password) {
      return res.status(400).json({ error: 'Все поля обязательны' });
    }

    if (!email.includes('@')) {
      return res.status(400).json({ error: 'Некорректный email' });
    }

    // Проверка существования пользователя
    const [user] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (user.lenght > 0) {
      return res.status(409).json({ error: 'Пользователь уже существует' });
    }

    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Сохранение пользователя
    await db.query(
      'INSERT INTO users (username, subname, email, password) VALUES (?, ?, ?, ?)',
      [username, subname, email, hashedPassword]
    );

    res.status(201).json({ message: 'Регистрация успешна' });
  } catch (err) {
    console.error('Ошибка регистрации:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Логин
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const db = await createDbConnection();

    if (!email || !password) {
      return res.status(400).json({ error: 'Email и пароль обязательны' });
    }

    const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    db.end();
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Неверные данные' });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Неверные данные' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    res.json({
      token,
      username: user.username,
      expiresIn: 3600
    });
  } catch (err) {
    console.error('Ошибка входа:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});


// Получение данных пользователя
app.get('/get-user', authenticateJWT, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT username, subname, email FROM users WHERE email = ?',
      [req.user.email]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Ошибка получения данных:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Обновление данных пользователя
app.put('/update-user', authenticateJWT, async (req, res) => {
  try {
    const { username, subname, email, currentPassword, newPassword } = req.body;

    if (!username || !subname || !email) {
      return res.status(400).json({ error: 'Обязательные поля: имя, фамилия, email' });
    }

    // Получаем полные данные пользователя
    const [users] = await db.query(
      'SELECT * FROM users WHERE email = ?',
      [req.user.email]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    const user = users[0];

    // Если меняется пароль
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ error: 'Текущий пароль обязателен' });
      }

      // Проверяем что user.password существует
      if (!user.password) {
        return res.status(500).json({ error: 'Ошибка сервера: пароль пользователя не найден' });
      }

      // Сравниваем пароли
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return res.status(401).json({ error: 'Неверный пароль' });
      }

      // Хешируем новый пароль
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Обновляем с новым паролем
      await db.query(
        'UPDATE users SET username = ?, subname = ?, email = ?, password = ? WHERE email = ?',
        [username, subname, email, hashedPassword, req.user.email]
      );
    } else {
      // Без смены пароля
      await db.query(
        'UPDATE users SET username = ?, subname = ?, email = ? WHERE email = ?',
        [username, subname, email, req.user.email]
      );
    }

    res.json({ message: 'Данные обновлены' });
  } catch (err) {
    console.error('Ошибка обновления:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Обработка 404
app.use((req, res) => {
  res.status(404).json({ error: 'Не найдено' });
});

// Обработка ошибок
app.use((err, req, res, next) => {
  console.error('Ошибка:', err.stack);
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`);
});