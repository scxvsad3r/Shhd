const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { Client } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// بيانات الاتصال بقاعدة البيانات (ضع هنا رابط الاتصال الخاص بك)
const connectionString = 'postgresql://postgres:OESSTSEDkYaSrecZjjNqVwEVscWxPnZT@interchange.proxy.rlwy.net:34758/railway';

const client = new Client({
  connectionString,
});

client.connect().then(() => {
  console.log('Connected to PostgreSQL');
}).catch(console.error);

// إعدادات الجلسة
app.use(session({
  secret: 'secret_store_key_123',
  resave: false,
  saveUninitialized: false,
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware لحماية صفحات لوحة التحكم
function checkAuth(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login.html');
  }
}

// صفحة لوحة التحكم محمية
app.get('/dashboard.html', checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// تسجيل مستخدم جديد
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.json({ success: false, message: 'جميع الحقول مطلوبة.' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    // تحقق من وجود المستخدم مسبقًا
    const userExist = await client.query('SELECT id FROM users WHERE email=$1', [email]);
    if (userExist.rows.length > 0) {
      return res.json({ success: false, message: 'البريد الإلكتروني مستخدم مسبقًا.' });
    }
    await client.query('INSERT INTO users (name, email, password) VALUES ($1, $2, $3)', [name, email, hashedPassword]);
    res.json({ success: true, message: 'تم إنشاء الحساب بنجاح!' });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: 'حدث خطأ أثناء التسجيل.' });
  }
});

// تسجيل الدخول
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.json({ success: false, message: 'يرجى ملء جميع الحقول.' });
  }
  try {
    const userRes = await client.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = userRes.rows[0];
    if (!user) {
      return res.json({ success: false, message: 'البريد الإلكتروني غير مسجل.' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.json({ success: false, message: 'كلمة المرور غير صحيحة.' });
    }
    req.session.userId = user.id;
    res.json({ success: true, message: 'تم تسجيل الدخول بنجاح!' });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: 'حدث خطأ أثناء تسجيل الدخول.' });
  }
});

// تسجيل خروج
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// بدء الخادم
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
