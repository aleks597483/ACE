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
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
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
      { expiresIn: '1000h' }
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



// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`);
});

// Добавим новый маршрут для получения категорий
app.get('/api/categories', async (req, res) => {
  try {
    const db = await createDbConnection();
    
    // Получаем категории с иерархией
    const [categories] = await db.query(`
      WITH RECURSIVE category_tree AS (
        SELECT 
          category_id,
          category_name,
          category_description,
          parent_category_id,
          icon_class,
          0 AS level
        FROM categories
        WHERE parent_category_id IS NULL
        
        UNION ALL
        
        SELECT 
          c.category_id,
          c.category_name,
          c.category_description,
          c.parent_category_id,
          c.icon_class,
          ct.level + 1
        FROM categories c
        JOIN category_tree ct ON c.parent_category_id = ct.category_id
      )
      SELECT * FROM category_tree
      ORDER BY parent_category_id IS NULL DESC, category_id ASC
    `);
    
    db.end();
    
    res.json({ success: true, categories });
  } catch (err) {
    console.error('Ошибка получения категорий:', err);
    res.status(500).json({ success: false, error: 'Ошибка сервера' });
  }
});

// ==================== Поиск товаров ====================

// Полнотекстовый поиск товаров
app.get('/api/search', async (req, res) => {
  try {
    const { query, page = 1, limit = 40 } = req.query;
    
    if (!query || query.trim().length < 2) {
      return res.status(400).json({ 
        error: 'Поисковый запрос должен содержать минимум 2 символа' 
      });
    }

    const offset = (page - 1) * limit;
    const db = await createDbConnection();

    // Выполняем поиск с полнотекстовым индексом

    const [products] = await db.query(`
        SELECT 
            p.*,
            MATCH(p.product_name, p.description) AGAINST(? IN BOOLEAN MODE) AS relevance
        FROM products p
        WHERE MATCH(p.product_name, p.description) AGAINST(? IN BOOLEAN MODE)
        OR p.product_code LIKE ?
        ORDER BY relevance DESC
        LIMIT ? OFFSET ?
    `, [query, query, `%${query}%`, parseInt(limit), parseInt(offset)]);

    // Получаем общее количество результатов
    const [[{ total }]] = await db.query(`
      SELECT COUNT(*) as total
      FROM products
      WHERE MATCH(product_name, description) AGAINST(? IN BOOLEAN MODE)
    `, [query, `%${query}%`]);

    db.end();

    res.json({
      success: true,
      query,
      page: parseInt(page),
      total,
      totalPages: Math.ceil(total / limit),
      products
    });
  } 
    catch (err) {
    console.error('Ошибка поиска товаров:', err);
    res.status(500).json({ 
      success: false,
      error: 'Ошибка при выполнении поиска' 
    });
  }
});

// Автодополнение поисковых запросов
app.get('/api/search/suggest', async (req, res) => {
  try {
    const { query } = req.query;
    
    if (!query || query.trim().length < 2) {
      return res.json([]);
    }

    const db = await createDbConnection();
    
    const [suggestions] = await db.query(`
      SELECT product_name 
      FROM products 
      WHERE product_name LIKE ?
      GROUP BY product_name
      LIMIT 5
    `, [`%${query}%`]);

    db.end();

    res.json(suggestions.map(s => s.product_name));
  } catch (err) {
    console.error('Ошибка автодополнения:', err);
    res.json([]);
  }
});

// Новинки (последние добавленные товары)
app.get('/api/products/new', async (req, res) => {
  try {
    const db = await createDbConnection();
    const [products] = await db.query(`
      SELECT * FROM products 
      ORDER BY created_at DESC 
      LIMIT 10
    `);
    db.end();
    
    res.json({ success: true, products });
  } catch (err) {
    console.error('Ошибка получения новинок:', err);
    res.status(500).json({ success: false, error: 'Ошибка сервера' });
  }
});

app.get('/api/product/:id', async (req, res) => {
    try {
        const productId = req.params.id;
        const db = await createDbConnection();
        const [products] = await db.query('SELECT * FROM products WHERE product_id = ?', [productId]);
        db.end();
        
        if (products.length === 0) {
            return res.status(404).json({ error: 'Товар не найден' });
        }
        
        res.json({ success: true, product: products[0] });
    } catch (err) {
        console.error('Ошибка получения товара:', err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Получение информации о бренде
app.get('/api/brand/:brandId', async (req, res) => {
  try {
    const { brandId } = req.params;
    const db = await createDbConnection();
    
    const [[brand]] = await db.query(`
      SELECT brand_id, brand_name, brand_logo 
      FROM brands 
      WHERE brand_id = ?
    `, [brandId]);
    
    db.end();
    
    if (!brand) {
      return res.status(404).json({ success: false, error: 'Бренд не найден' });
    }
    
    res.json({ success: true, brand });
  } catch (err) {
    console.error('Ошибка получения бренда:', err);
    res.status(500).json({ success: false, error: 'Ошибка сервера' });
  }
});

// Лидеры продаж (наиболее популярные товары)
app.get('/api/products/top', async (req, res) => {
  try {
    const db = await createDbConnection();
    const [products] = await db.query(`
      SELECT * FROM products 
      ORDER BY sales_count DESC, rating DESC 
      LIMIT 10
    `);
    db.end();
    
    res.json({ success: true, products });
  } catch (err) {
    console.error('Ошибка получения лидеров продаж:', err);
    res.status(500).json({ success: false, error: 'Ошибка сервера' });
  }
});

// Получение товаров по категории
app.get('/api/products/category/:categoryId', async (req, res) => {
  try {
    const { categoryId } = req.params;
    const db = await createDbConnection();

    const [products] = await db.query(`
      SELECT p.* 
      FROM products p
      JOIN product_categories pc ON p.product_id = pc.product_id
      WHERE pc.category_id = ?
      ORDER BY p.created_at DESC
    `, [categoryId]);

    db.end();
    res.json({ success: true, products });
  } catch (err) {
    console.error('Ошибка получения товаров:', err);
    res.status(500).json({ success: false, error: 'Ошибка сервера' });
  }
});

// Получение списка всех брендов
app.get('/api/brands', async (req, res) => {
  try {
    const db = await createDbConnection();
    const [brands] = await db.query(`
      SELECT 
        brand_id AS id,
        brand_name AS name,
        brand_logo AS logo,
        brand_description AS description
      FROM brands
      ORDER BY brand_name
    `);
    db.end();
    res.json({ success: true, brands });
  } catch (err) {
    console.error('Ошибка получения брендов:', err);
    res.status(500).json({ success: false, error: 'Ошибка сервера' });
  }
});

// Получение товаров по ID бренда
app.get('/api/products/brands/:brandId', async (req, res) => {
  try {
    const { brandId } = req.params;
    const db = await createDbConnection();
    
    // Получаем сначала имя бренда
    const [[brand]] = await db.query('SELECT brand_name FROM brands WHERE brand_id = ?', [brandId]);
    if (!brand) {
      db.end();
      return res.status(404).json({ success: false, error: 'Бренд не найден' });
    }
    const [products] = await db.query(`
      SELECT p.*, b.brand_name 
      FROM products p
      JOIN brands b ON p.brand_id = b.brand_id
      WHERE p.brand_id = ?
    `, [brandId]);

    db.end();
    
    res.json({ 
      success: true, 
      products,
      brand: products.length > 0 ? products[0].brand_name : null
    });
  } catch (err) {
    console.error('Ошибка получения товаров бренда:', err);
    res.status(500).json({ success: false, error: 'Ошибка сервера' });
  }
});

// Получение изображений товара (только дополнительных)
app.get('/api/product-images/:productId', async (req, res) => {
    try {
        const { productId } = req.params;
        const db = await createDbConnection();
        
        // Получаем только дополнительные изображения (где is_main = 0 или null)
        const [images] = await db.query(
            'SELECT image_url FROM product_images WHERE product_id = ? AND (is_main IS NULL OR is_main = 0) ORDER BY image_id ASC',
            [productId]
        );
        
        db.end();
        res.json({ success: true, images });
    } catch (err) {
        console.error('Ошибка получения изображений товара:', err);
        res.status(500).json({ success: false, error: 'Ошибка сервера' });
    }
});

app.get('/api/product/:id', async (req, res) => {
    try {
        const productId = req.params.id;
        const db = await createDbConnection();
        
        // Запрос с добавлением количества отзывов
        const [products] = await db.query(`
            SELECT 
                p.*,
                COUNT(r.review_id) AS reviews_count
            FROM products p
            LEFT JOIN reviews r ON p.product_id = r.product_id
            WHERE p.product_id = ?
            GROUP BY p.product_id
        `, [productId]);
        
        db.end();
        
        if (products.length === 0) {
            return res.status(404).json({ error: 'Товар не найден' });
        }
        
        res.json({ 
            success: true, 
            product: {
                ...products[0],
                reviews_count: parseInt(products[0].reviews_count) || 0
            }
        });
    } catch (err) {
        console.error('Ошибка получения товара:', err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});
// Получение содержимого корзины
app.get('/api/cart', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const userId = req.user.userId;
    
    const [items] = await db.query(
      `SELECT c.*, p.main_image, p.product_code, p.stock_quantity 
       FROM cart c
       LEFT JOIN products p ON c.product_id = p.product_id
       WHERE c.user_id = ?`,
      [userId]
    );

    res.json({ success: true, items });
  } catch (err) {
    console.error('Ошибка получения корзины:', err);
    res.status(500).json({ success: false, error: 'Ошибка сервера' });
  } finally {
    db.end();
  }
});
// Удаление товара из корзины
app.delete('/api/cart/remove/:id', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const { id } = req.params;
    const userId = req.user.userId;

    const [existingItems] = await db.query(
      'SELECT * FROM cart WHERE id = ? AND user_id = ?',
      [id, userId]
    );

    if (existingItems.length === 0) {
      return res.status(404).json({ success: false, error: 'Товар не найден в корзине' });
    }

    await db.query('DELETE FROM cart WHERE id = ?', [id]);

    res.json({ success: true, message: 'Товар удален из корзины' });
  } catch (err) {
    console.error('Ошибка удаления из корзины:', err);
    res.status(500).json({ success: false, error: 'Ошибка сервера' });
  } finally {
    db.end();
  }
});
// Добавление товара в корзину с проверкой наличия
app.post('/api/cart/add', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const { product_id, product_name, price, quantity } = req.body;
    const userId = req.user.userId;

    // Проверяем наличие товара
    const [product] = await db.query(
      'SELECT stock_quantity FROM products WHERE product_id = ?',
      [product_id]
    );

    if (product.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Товар не найден' 
      });
    }

    const availableQuantity = product[0].stock_quantity;
    const [existingItems] = await db.query(
      'SELECT * FROM cart WHERE user_id = ? AND product_id = ?',
      [userId, product_id]
    );

    // Рассчитываем общее количество в корзине (существующее + новое)
    const totalInCart = existingItems.length > 0 
      ? existingItems[0].quantity + quantity 
      : quantity;

    if (totalInCart > availableQuantity) {
      return res.status(400).json({
        success: false,
        error: `Недостаточно товара в наличии. Доступно: ${availableQuantity}`,
        available: availableQuantity
      });
    }

    if (existingItems.length > 0) {
      await db.query(
        'UPDATE cart SET quantity = quantity + ? WHERE id = ?',
        [quantity, existingItems[0].id]
      );
    } else {
      await db.query(
        'INSERT INTO cart (user_id, product_id, product_name, price, quantity) VALUES (?, ?, ?, ?, ?)',
        [userId, product_id, product_name, price, quantity]
      );
    }

    res.json({ 
      success: true, 
      message: 'Товар добавлен в корзину',
      available: availableQuantity - totalInCart
    });
  } catch (err) {
    console.error('Ошибка добавления в корзину:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Ошибка сервера' 
    });
  } finally {
    db.end();
  }
});

// Обновление количества товара в корзине с проверкой наличия
app.put('/api/cart/update/:id', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const { id } = req.params;
    const { quantity } = req.body;
    const userId = req.user.userId;

    // Получаем текущий товар в корзине
    const [existingItems] = await db.query(
      'SELECT * FROM cart WHERE id = ? AND user_id = ?',
      [id, userId]
    );

    if (existingItems.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Товар не найден в корзине' 
      });
    }

    const item = existingItems[0];
    
    // Проверяем наличие товара
    const [product] = await db.query(
      'SELECT stock_quantity FROM products WHERE product_id = ?',
      [item.product_id]
    );

    if (product.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Товар больше не доступен' 
      });
    }

    const availableQuantity = product[0].stock_quantity;

    if (quantity > availableQuantity) {
      return res.status(400).json({
        success: false,
        error: `Недостаточно товара в наличии. Доступно: ${availableQuantity}`,
        available: availableQuantity
      });
    }

    if (quantity <= 0) {
      await db.query('DELETE FROM cart WHERE id = ?', [id]);
    } else {
      await db.query(
        'UPDATE cart SET quantity = ? WHERE id = ?',
        [quantity, id]
      );
    }

    res.json({ 
      success: true, 
      message: 'Корзина обновлена',
      available: availableQuantity - quantity
    });
  } catch (err) {
    console.error('Ошибка обновления корзины:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Ошибка сервера' 
    });
  } finally {
    db.end();
  }
});

// Оформление заказа с обновлением остатков
app.post('/api/checkout', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const userId = req.user.userId;
    
    // Получаем корзину с информацией о товарах
    const [cartItems] = await db.query(
      `SELECT c.*, p.main_image, p.product_code, p.stock_quantity 
       FROM cart c
       JOIN products p ON c.product_id = p.product_id
       WHERE c.user_id = ?`,
      [userId]
    );

    if (cartItems.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Корзина пуста' 
      });
    }

    // Проверяем наличие всех товаров
    for (const item of cartItems) {
      if (item.stock_quantity < item.quantity) {
        return res.status(400).json({
          success: false,
          error: `Недостаточно товара "${item.product_name}" в наличии. Доступно: ${item.stock_quantity}`,
          product_id: item.product_id,
          available: item.stock_quantity
        });
      }
    }

    // Начинаем транзакцию
    await db.query('START TRANSACTION');

    // Рассчитываем общую сумму
    const totalAmount = cartItems.reduce((sum, item) => sum + (item.price * item.quantity), 0);

    // Создаем заказ
    const [orderResult] = await db.query(
      'INSERT INTO orders (user_id, total_amount, status) VALUES (?, ?, ?)',
      [userId, totalAmount, 'Новый']
    );
    
    const orderId = orderResult.insertId;

    // Добавляем товары в заказ и обновляем остатки (разделенные запросы)
    for (const item of cartItems) {
      // Вставляем запись о товаре в заказе
      await db.query(
        `INSERT INTO order_items (order_id, product_id, product_name, price, quantity) 
         VALUES (?, ?, ?, ?, ?)`,
        [orderId, item.product_id, item.product_name, item.price, item.quantity]
      );
      
      // Обновляем количество товара на складе и увеличиваем счетчик продаж
      await db.query(
        `UPDATE products 
         SET stock_quantity = stock_quantity - ?, 
             sales_count = IFNULL(sales_count, 0) + ? 
         WHERE product_id = ?`,
        [item.quantity, item.quantity, item.product_id]
      )
    }

    // Очищаем корзину
    await db.query('DELETE FROM cart WHERE user_id = ?', [userId]);

    // Фиксируем транзакцию
    await db.query('COMMIT');

    res.json({ 
      success: true, 
      message: 'Заказ успешно оформлен',
      orderId: orderId,
      totalAmount: totalAmount
    });
  } catch (err) {
    // Откатываем транзакцию при ошибке
    await db.query('ROLLBACK');
    console.error('Ошибка оформления заказа:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Ошибка сервера при оформлении заказа',
      details: err.message
    });
  } finally {
    db.end();
  }
});

// Добавление товара в список сравнений
app.post('/api/compare/add', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const { product_id, category_id } = req.body;
    const userId = req.user.userId;

    // Проверяем, существует ли уже такой товар в списке сравнений пользователя
    const [existing] = await db.query(
      'SELECT * FROM product_comparisons WHERE user_id = ? AND product_id = ?',
      [userId, product_id]
    );

    if (existing.length > 0) {
      return res.status(409).json({ 
        success: false, 
        error: 'Товар уже в списке сравнений' 
      });
    }

    // Добавляем товар в список сравнений
    await db.query(
      'INSERT INTO product_comparisons (user_id, product_id, category_id) VALUES (?, ?, ?)',
      [userId, product_id, category_id]
    );

    res.json({ 
      success: true, 
      message: 'Товар добавлен в список сравнений' 
    });
  } catch (err) {
    console.error('Ошибка добавления в сравнения:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Ошибка сервера' 
    });
  } finally {
    db.end();
  }
});

// Удаление товара из списка сравнений
app.delete('/api/compare/remove', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const { product_id } = req.body;
    const userId = req.user.userId;

    // Удаляем товар из списка сравнений
    const [result] = await db.query(
      'DELETE FROM product_comparisons WHERE user_id = ? AND product_id = ?',
      [userId, product_id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Товар не найден в списке сравнений' 
      });
    }

    res.json({ 
      success: true, 
      message: 'Товар удален из списка сравнений' 
    });
  } catch (err) {
    console.error('Ошибка удаления из сравнений:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Ошибка сервера' 
    });
  } finally {
    db.end();
  }
});

// Проверка наличия товара в списке сравнений
app.get('/api/compare/check', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const { product_id } = req.query;
    const userId = req.user.userId;

    const [result] = await db.query(
      'SELECT id FROM product_comparisons WHERE user_id = ? AND product_id = ?',
      [userId, product_id]
    );

    res.json({ 
      success: true, 
      inCompareList: result.length > 0 
    });
  } catch (err) {
    console.error('Ошибка проверки сравнений:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Ошибка сервера' 
    });
  } finally {
    db.end();
  }
});

// Получение списка категорий для сравнения
app.get('/api/compare/categories', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const userId = req.user.userId;
    
    // Получаем уникальные категории из списка сравнений пользователя
    const [categories] = await db.query(`
      SELECT DISTINCT c.category_id, c.category_name 
      FROM product_comparisons pc
      JOIN categories c ON pc.category_id = c.category_id
      WHERE pc.user_id = ?
    `, [userId]);

    res.json({ success: true, categories });
  } catch (err) {
    console.error('Ошибка получения категорий для сравнения:', err);
    res.status(500).json({ success: false, error: 'Ошибка сервера' });
  } finally {
    db.end();
  }
});

// Получение характеристик товаров для сравнения по категории
app.get('/api/compare/products/:categoryId', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const { categoryId } = req.params;
    const userId = req.user.userId;

    // 1. Получаем список товаров для сравнения в этой категории
    const [products] = await db.query(`
      SELECT p.* 
      FROM product_comparisons pc
      JOIN products p ON pc.product_id = p.product_id
      WHERE pc.user_id = ? AND pc.category_id = ?
    `, [userId, categoryId]);

    if (products.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Товар удалён' 
      });
    }

    // 2. Определяем таблицу характеристик для этой категории
    const [category] = await db.query(
      'SELECT specs_table FROM categories WHERE category_id = ?',
      [categoryId]
    );

    if (!category[0]?.specs_table) {
      return res.status(404).json({ 
        success: false, 
        error: 'Таблица характеристик не найдена для этой категории' 
      });
    }

    const specsTable = category[0].specs_table;

    // 3. Получаем характеристики для каждого товара
    const productsWithSpecs = await Promise.all(products.map(async (product) => {
      const [specs] = await db.query(
        `SELECT * FROM ${specsTable} WHERE product_id = ?`,
        [product.product_id]
      );
      return {
        ...product,
        specs: specs[0] || {}
      };
    }));

    // 4. Получаем список всех возможных характеристик для этой категории
    const [allSpecs] = await db.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_NAME = ? AND COLUMN_NAME NOT IN ('product_id', 'id', 'created_at', 'updated_at', 'category_id')
      ORDER BY ORDINAL_POSITION
    `, [specsTable]);

    const specKeys = allSpecs.map(spec => spec.COLUMN_NAME);

    res.json({ 
      success: true, 
      products: productsWithSpecs,
      specKeys,
      categoryName: category[0].category_name
    });
  } catch (err) {
    console.error('Ошибка получения характеристик для сравнения:', err);
    res.status(500).json({ success: false, error: 'Ошибка сервера' });
  } finally {
    db.end();
  }
});

// Получение отзывов о товаре
app.get('/api/product/:id/reviews', async (req, res) => {
  const db = await createDbConnection();
  try {
    const { id } = req.params;
    
    const [reviews] = await db.query(`
      SELECT 
        r.review_id,
        r.product_id,
        r.user_id,
        r.rating,
        r.pros,
        r.cons,
        r.comment,
        r.created_at,
        u.username as author
      FROM reviews r
      JOIN users u ON r.user_id = u.id
      WHERE r.product_id = ?
      ORDER BY r.created_at DESC
    `, [id]);

    const [stats] = await db.query(`
      SELECT 
        COUNT(*) as total_reviews,
        AVG(rating) as average_rating,
        SUM(CASE WHEN rating >= 4 THEN 1 ELSE 0 END) as recommended_count
      FROM reviews
      WHERE product_id = ?
    `, [id]);

    db.end();

    res.json({ 
      success: true,
      reviews,
      stats: {
        total_reviews: stats[0].total_reviews || 0,
        average_rating: parseFloat(stats[0].average_rating) || 0,
        recommended_percentage: stats[0].total_reviews > 0 
          ? Math.round((stats[0].recommended_count / stats[0].total_reviews) * 100)
          : 0
      }
    });
  } catch (err) {
    console.error('Ошибка получения отзывов:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Ошибка сервера при получении отзывов' 
    });
    if (db && db.end) db.end();
  }
});

// Добавление отзыва
app.post('/api/reviews/add', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const { product_id, rating, pros, cons, comment } = req.body; // Получаем 3 отдельных поля
    const user_id = req.user.userId;

    // Валидация
    if (!product_id || !rating || rating < 1 || rating > 5) {
      return res.status(400).json({ 
        success: false, 
        error: 'Укажите рейтинг от 1 до 5' 
      });
    }

    // Проверка существования товара
    const [product] = await db.query(
      'SELECT 1 FROM products WHERE product_id = ?',
      [product_id]
    );

    if (product.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Товар не найден' 
      });
    }

    // Проверка дубликата отзыва
    const [existing] = await db.query(
      'SELECT 1 FROM reviews WHERE user_id = ? AND product_id = ?',
      [user_id, product_id]
    );

    if (existing.length > 0) {
      return res.status(409).json({ 
        success: false, 
        error: 'Вы уже оставляли отзыв на этот товар' 
      });
    }

    // Добавление отзыва с тремя полями
    await db.query(
      `INSERT INTO reviews 
       (product_id, user_id, rating, pros, cons, comment) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [product_id, user_id, rating, pros || null, cons || null, comment || null]
    );

    // Обновляем рейтинг товара
    await db.query(`
      UPDATE products p SET
        rating = (SELECT AVG(rating) FROM reviews WHERE product_id = p.product_id),
        reviews_count = (SELECT COUNT(*) FROM reviews WHERE product_id = p.product_id)
      WHERE p.product_id = ?
    `, [product_id]);

    res.json({ 
      success: true,
      message: 'Отзыв сохранён'
    });
  } catch (err) {
    console.error('Ошибка:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Ошибка сервера' 
    });
  } finally {
    db.end();
  }
});

// Получение характеристик товара
app.get('/api/product/:id/specs', async (req, res) => {
    const db = await createDbConnection();
    try {
        const { id } = req.params;
        
        // 1. Сначала получаем категорию товара
        const [product] = await db.query(
            'SELECT category_id FROM products WHERE product_id = ?',
            [id]
        );
        
        if (product.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Товар не найден' 
            });
        }
        
        const categoryId = product[0].category_id;
        
        // 2. Получаем название таблицы характеристик для этой категории
        const [category] = await db.query(
            'SELECT specs_table FROM categories WHERE category_id = ?',
            [categoryId]
        );
        
        if (!category[0]?.specs_table) {
            return res.status(404).json({ 
                success: false, 
                error: 'Характеристики не найдены для этой категории' 
            });
        }
        
        const specsTable = category[0].specs_table;
        
        // 3. Получаем характеристики товара
        const [specs] = await db.query(
            `SELECT * FROM ${specsTable} WHERE product_id = ?`,
            [id]
        );
        
        if (specs.length === 0) {
            return res.json({ 
                success: true, 
                specs: {} 
            });
        }
        
        res.json({ 
            success: true, 
            specs: specs[0] 
        });
    } catch (err) {
        console.error('Ошибка получения характеристик:', err);
        res.status(500).json({ 
            success: false, 
            error: 'Ошибка сервера' 
        });
    } finally {
        db.end();
    }
});
// Добавление товара в избранное
app.post('/api/wishlist/add', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const { product_id } = req.body;
    const userId = req.user.userId;

    // Проверяем существование товара
    const [product] = await db.query(
      'SELECT 1 FROM products WHERE product_id = ?',
      [product_id]
    );

    if (product.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Товар не найден' 
      });
    }

    // Проверяем, не добавлен ли уже товар
    const [existing] = await db.query(
      'SELECT 1 FROM wishlist WHERE user_id = ? AND product_id = ?',
      [userId, product_id]
    );

    if (existing.length > 0) {
      return res.status(409).json({ 
        success: false, 
        error: 'Товар уже в избранном' 
      });
    }

    // Добавляем товар в избранное
    await db.query(
      'INSERT INTO wishlist (user_id, product_id) VALUES (?, ?)',
      [userId, product_id]
    );

    res.json({ 
      success: true, 
      message: 'Товар добавлен в избранное' 
    });
  } catch (err) {
    console.error('Ошибка добавления в избранное:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Ошибка сервера' 
    });
  } finally {
    db.end();
  }
});
// Проверка наличия товара в избранном
app.get('/api/wishlist/check', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const { product_id } = req.query;
    const userId = req.user.userId;

    const [result] = await db.query(
      'SELECT wishlist_id FROM wishlist WHERE user_id = ? AND product_id = ?',
      [userId, product_id]
    );

    res.json({ 
      success: true, 
      inWishlist: result.length > 0 
    });
  } catch (err) {
    console.error('Ошибка проверки избранного:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Ошибка сервера' 
    });
  } finally {
    db.end();
  }
});
// Получение списка избранных товаров
app.get('/api/wishlist', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const userId = req.user.userId;
    
    const [items] = await db.query(`
      SELECT 
        p.product_id,
        p.product_name,
        p.price,
        p.rating,
        p.main_image
      FROM wishlist w
      JOIN products p ON w.product_id = p.product_id
      WHERE w.user_id = ?
    `, [userId]);

    res.json({ success: true, items });
  } catch (err) {
    console.error('Ошибка получения избранного:', err);
    res.status(500).json({ success: false, error: 'Ошибка сервера' });
  } finally {
    db.end();
  }
});

// Удаление товара из избранного
app.delete('/api/wishlist/remove/:productId', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const { productId } = req.params;
    const userId = req.user.userId;

    const [result] = await db.query(
      'DELETE FROM wishlist WHERE user_id = ? AND product_id = ?',
      [userId, productId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Товар не найден в избранном' 
      });
    }

    res.json({ success: true, message: 'Товар удален из избранного' });
  } catch (err) {
    console.error('Ошибка удаления из избранного:', err);
    res.status(500).json({ success: false, error: 'Ошибка сервера' });
  } finally {
    db.end();
  }
});
// Получение заказов пользователя с их содержимым
app.get('/api/orders', authenticateJWT, async (req, res) => {
  const db = await createDbConnection();
  try {
    const userId = req.user.userId;
    
    // Получаем список заказов пользователя
    const [orders] = await db.query(`
      SELECT 
        id,
        total_amount,
        status,
        DATE_FORMAT(created_at, '%d.%m.%Y %H:%i') as formatted_date
      FROM orders
      WHERE user_id = ?
      ORDER BY created_at DESC
    `, [userId]);

    // Для каждого заказа получаем его содержимое
    const ordersWithItems = await Promise.all(orders.map(async (order) => {
      const [items] = await db.query(`
        SELECT 
          oi.product_id,
          oi.product_name,
          oi.price,
          oi.quantity,
          p.main_image
        FROM order_items oi
        LEFT JOIN products p ON oi.product_id = p.product_id
        WHERE oi.order_id = ?
      `, [order.id]);
      
      return {
        ...order,
        items: items.map(item => ({
          ...item,
          total: item.price * item.quantity
        }))
      };
    }));

    res.json({ 
      success: true, 
      orders: ordersWithItems 
    });
  } catch (err) {
    console.error('Ошибка получения заказов:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Ошибка сервера при получении заказов' 
    });
  } finally {
    db.end();
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