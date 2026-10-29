'use strict';

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATABASE_PATH = process.env.DATABASE_PATH || path.join(__dirname, 'auraic.db');

if (!ADMIN_USERNAME || !ADMIN_PASSWORD_HASH || !SESSION_SECRET) {
console.error(
'Missing required environment variables: ADMIN_USERNAME, ADMIN_PASSWORD_HASH, SESSION_SECRET'
);
process.exit(1);
}

if (SESSION_SECRET.length < 32) {
console.error('SESSION_SECRET must contain at least 32 characters.');
process.exit(1);
}

if (!fs.existsSync(path.dirname(DATABASE_PATH))) {
fs.mkdirSync(path.dirname(DATABASE_PATH), { recursive: true });
}

const db = new Database(DATABASE_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS products (
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT NOT NULL,
description TEXT NOT NULL DEFAULT '',
price INTEGER NOT NULL CHECK(price >= 0),
image TEXT NOT NULL DEFAULT '',
back_image TEXT NOT NULL DEFAULT '',
color TEXT NOT NULL DEFAULT '',
sizes TEXT NOT NULL DEFAULT '[]',
stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
active INTEGER NOT NULL DEFAULT 1,
created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
id INTEGER PRIMARY KEY AUTOINCREMENT,
order_code TEXT NOT NULL UNIQUE,
customer_name TEXT NOT NULL,
phone TEXT NOT NULL,
address TEXT NOT NULL,
payment_method TEXT NOT NULL CHECK(payment_method IN ('COD', 'UPI')),
payment_status TEXT NOT NULL DEFAULT 'PENDING',
order_status TEXT NOT NULL DEFAULT 'NEW',
items_json TEXT NOT NULL,
total INTEGER NOT NULL CHECK(total >= 0),
created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_attempts (
id INTEGER PRIMARY KEY AUTOINCREMENT,
ip TEXT NOT NULL,
attempted_at INTEGER NOT NULL
);
`);

app.disable('x-powered-by');
app.use(helmet({
contentSecurityPolicy: false
}));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

app.use(session({
name: 'auraic.sid',
secret: SESSION_SECRET,
resave: false,
saveUninitialized: false,
cookie: {
httpOnly: true,
secure: NODE_ENV === 'production',
sameSite: 'lax',
maxAge: 1000 * 60 * 60 * 4
}
}));

app.use(express.static(path.join(__dirname, 'public')));

function adminOnly(req, res, next) {
if (req.session && req.session.admin === true) {
return next();
}
return res.status(401).json({ error: 'Admin login required.' });
}

function validText(value, maxLength = 500) {
return typeof value === 'string' &&
value.trim().length > 0 &&
value.trim().length <= maxLength;
}

function safeProduct(row) {
if (!row) return null;
return {
...row,
sizes: JSON.parse(row.sizes || '[]'),
active: Boolean(row.active)
};
}

function parseProductInput(body) {
const name = typeof body.name === 'string' ? body.name.trim() : '';
const description = typeof body.description === 'string' ? body.description.trim() : '';
const image = typeof body.image === 'string' ? body.image.trim() : '';
const backImage = typeof body.back_image === 'string' ? body.back_image.trim() : '';
const color = typeof body.color === 'string' ? body.color.trim() : '';
const price = Number(body.price);
const stock = body.stock === undefined ? 0 : Number(body.stock);
const sizes = body.sizes === undefined ? [] : body.sizes;

if (!validText(name, 120)) {
throw new Error('Product name is required (maximum 120 characters).');
}
if (!Number.isSafeInteger(price) || price < 0) {
throw new Error('Price must be a non-negative whole number in rupees.');
}
if (!Number.isSafeInteger(stock) || stock < 0 || stock > 100000) {
throw new Error('Stock must be a valid non-negative whole number.');
}
if (!Array.isArray(sizes) || sizes.length > 20 ||
!sizes.every(size => typeof size === 'string' && size.length <= 20)) {
throw new Error('Sizes must be a list of short text values.');
}
if (description.length > 2000 || image.length > 1000 ||
backImage.length > 1000 || color.length > 80) {
throw new Error('One or more product fields are too long.');
}

return {
name,
description,
price,
image,
back_image: backImage,
color,
sizes: JSON.stringify(sizes),
stock
};
}

app.get('/api/health', (req, res) => {
res.json({ ok: true, service: 'AURAIC API' });
});

// Public: show active products only.
app.get('/api/products', (req, res) => {
const products = db.prepare("SELECT * FROM products WHERE active = 1 ORDER BY created_at DESC, id DESC").all().map(safeProduct);

res.json({ products });
});

// Login rate limit: maximum 10 attempts per IP in 15 minutes.
app.post('/api/admin/login', (req, res, next) => {
try {
const ip = req.ip || req.socket.remoteAddress || 'unknown';
const now = Date.now();
const windowStart = now - 15 * 60 * 1000;

db.prepare('DELETE FROM login_attempts WHERE attempted_at < ?').run(windowStart);

const attempts = db.prepare(`
  SELECT COUNT(*) AS count
  FROM login_attempts
  WHERE ip = ? AND attempted_at >= ?
`).get(ip).count;

if (attempts >= 10) {
  return res.status(429).json({
    error: 'Too many login attempts. Please try again later.'
  });
}

const username = req.body.username;
const password = req.body.password;

if (typeof username !== 'string' || typeof password !== 'string' ||
    username.length > 100 || password.length > 200) {
  return res.status(400).json({ error: 'Invalid login details.' });
}

const validUsername = username === ADMIN_USERNAME;
const validPassword = bcrypt.compareSync(password, ADMIN_PASSWORD_HASH);

if (!validUsername || !validPassword) {
  db.prepare(`
    INSERT INTO login_attempts (ip, attempted_at)
    VALUES (?, ?)
  `).run(ip, now);

  return res.status(401).json({ error: 'Incorrect username or password.' });
}

req.session.regenerate((err) => {
  if (err) return next(err);

  req.session.admin = true;
  req.session.save((saveError) => {
    if (saveError) return next(saveError);
    res.json({ ok: true, message: 'Admin login successful.' });
  });
});

} catch (error) {
next(error);
}
});

app.post('/api/admin/logout', adminOnly, (req, res, next) => {
req.session.destroy((err) => {
if (err) return next(err);
res.clearCookie('auraic.sid');
res.json({ ok: true });
});
});

app.get('/api/admin/me', adminOnly, (req, res) => {
res.json({ authenticated: true });
});

// Admin: create a product.
app.post('/api/admin/products', adminOnly, (req, res, next) => {
try {
const product = parseProductInput(req.body);

const result = db.prepare(`
  INSERT INTO products
  (name, description, price, image, back_image, color, sizes, stock)
  VALUES
  (@name, @description, @price, @image, @back_image, @color, @sizes, @stock)
`).run(product);

const saved = db.prepare('SELECT * FROM products WHERE id = ?')
  .get(result.lastInsertRowid);

res.status(201).json({ product: safeProduct(saved) });

} catch (error) {
if (error.message && !error.status) {
return res.status(400).json({ error: error.message });
}
next(error);
}
});

// Admin: update a product.
app.put('/api/admin/products/:id', adminOnly, (req, res, next) => {
try {
const id = Number(req.params.id);
if (!Number.isSafeInteger(id) || id < 1) {
return res.status(400).json({ error: 'Invalid product ID.' });
}

const product = parseProductInput(req.body);
const result = db.prepare(`
  UPDATE products SET
    name = @name,
    description = @description,
    price = @price,
    image = @image,
    back_image = @back_image,
    color = @color,
    sizes = @sizes,
    stock = @stock
  WHERE id = @id
`).run({ ...product, id });

if (result.changes === 0) {
  return res.status(404).json({ error: 'Product not found.' });
}

const saved = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
res.json({ product: safeProduct(saved) });

} catch (error) {
res.status(400).json({ error: error.message || 'Invalid product data.' });
}
});

// Admin: soft-delete a product so historical orders remain intact.
app.delete('/api/admin/products/:id', adminOnly, (req, res) => {
const id = Number(req.params.id);
if (!Number.isSafeInteger(id) || id < 1) {
return res.status(400).json({ error: 'Invalid product ID.' });
}

const result = db.prepare(
'UPDATE products SET active = 0 WHERE id = ? AND active = 1'
).run(id);

if (!result.changes) {
return res.status(404).json({ error: 'Product not found.' });
}

res.json({ ok: true, message: 'Product removed from the store.' });
});

// Customer: create an order.
// The server calculates prices from the database, never from the browser.
app.post('/api/orders', (req, res, next) => {
try {
const { customer_name, phone, address, payment_method, items } = req.body;

if (!validText(customer_name, 120) ||
    !validText(phone, 30) ||
    !validText(address, 1000)) {
  return res.status(400).json({
    error: 'Please provide your name, phone number and delivery address.'
  });
}

if (!/^[0-9+\s()-]{7,20}$/.test(phone.trim())) {
  return res.status(400).json({ error: 'Please provide a valid phone number.' });
}

if (!['COD', 'UPI'].includes(payment_method)) {
  return res.status(400).json({ error: 'Choose COD or UPI.' });
}

if (!Array.isArray(items) || items.length < 1 || items.length > 30) {
  return res.status(400).json({ error: 'Your cart is empty or invalid.' });
}

const getProduct = db.prepare(
  'SELECT id, name, price, stock FROM products WHERE id = ? AND active = 1'
);

const orderItems = [];
let total = 0;

for (const item of items) {
  const productId = Number(item.product_id);
  const quantity = Number(item.quantity);

  if (!Number.isSafeInteger(productId) || productId < 1 ||
      !Number.isSafeInteger(quantity) || quantity < 1 || quantity > 20) {
    return res.status(400).json({ error: 'Invalid cart item.' });
  }

  const product = getProduct.get(productId);

  if (!product) {
    return res.status(400).json({ error: 'A selected product is unavailable.' });
  }

  if (quantity > product.stock) {
    return res.status(400).json({
      error: `Insufficient stock for ${product.name}.`
    });
  }

  total += product.price * quantity;

  if (!Number.isSafeInteger(total) || total > 100000000) {
    return res.status(400).json({ error: 'Order total is too large.' });
  }

  orderItems.push({
    product_id: product.id,
    name: product.name,
    unit_price: product.price,
    quantity
  });
}

const orderCode = 'AU-' + crypto.randomBytes(5).toString('hex').toUpperCase();

const createOrder = db.transaction(() => {
  for (const item of orderItems) {
    const result = db.prepare(`
      UPDATE products
      SET stock = stock - ?
      WHERE id = ? AND active = 1 AND stock >= ?
    `).run(item.quantity, item.product_id, item.quantity);

    if (!result.changes) {
      throw new Error('STOCK_CHANGED');
    }
  }

  db.prepare(`
    INSERT INTO orders
    (order_code, customer_name, phone, address, payment_method,
     payment_status, order_status, items_json, total)
    VALUES (?, ?, ?, ?, ?, 'PENDING', 'NEW', ?, ?)
  `).run(
    orderCode,
    customer_name.trim(),
    phone.trim(),
    address.trim(),
    payment_method,
    JSON.stringify(orderItems),
    total
  );
});

try {
  createOrder();
} catch (error) {
  if (error.message === 'STOCK_CHANGED') {
    return res.status(409).json({
      error: 'Stock changed while placing your order. Please refresh your cart.'
    });
  }
  throw error;
}

res.status(201).json({
  ok: true,
  order_code: orderCode,
  total,
  payment_method,
  payment_status: 'PENDING',
  message: 'Order received. Payment is not yet verified.'
});

} catch (error) {
next(error);
}
});

// Admin: view orders.
app.get('/api/admin/orders', adminOnly, (req, res) => {
const orders = db.prepare("SELECT * FROM orders ORDER BY id DESC LIMIT 200").all().map(order => ({
...order,
items: JSON.parse(order.items_json)
}));

res.json({ orders });
});

// Admin: update order status.
app.patch('/api/admin/orders/:id/status', adminOnly, (req, res) => {
const id = Number(req.params.id);
const status = req.body.status;
const allowed = ['NEW', 'CONFIRMED', 'PACKED', 'SHIPPED', 'DELIVERED', 'CANCELLED'];

if (!Number.isSafeInteger(id) || id < 1 || !allowed.includes(status)) {
return res.status(400).json({ error: 'Invalid order ID or status.' });
}

const result = db.prepare(
'UPDATE orders SET order_status = ? WHERE id = ?'
).run(status, id);

if (!result.changes) {
return res.status(404).json({ error: 'Order not found.' });
}

res.json({ ok: true });
});

// Unknown API routes return JSON; other pages use the homepage.
app.use('/api', (req, res) => {
res.status(404).json({ error: 'API route not found.' });
});

app.get('/', (req, res) => {
res.sendFile(path.join(__dirname, 'index.html'), (error) => {
if (error && !res.headersSent) {
res.status(404).send('AURAIC homepage not found. Check index.html in the repository root.');
}
});
});

app.use((err, req, res, next) => {
console.error('Request error:', err.message);
if (res.headersSent) return next(err);
res.status(500).json({ error: 'Server error. Please try again later.' });
});

const server = app.listen(PORT, '0.0.0.0', () => {
console.log("AURAIC server listening on port ${PORT}");
});

function shutdown() {
server.close(() => {
db.close();
process.exit(0);
});
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
