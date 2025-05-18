const mysql = require('mysql2/promise');
require('dotenv').config();

// Создаем пул соединений вместо одного подключения
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'Fara728396',
  database: process.env.DB_NAME || 'ace',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

console.log('✅ Пул соединений MySQL создан');
module.exports = pool;