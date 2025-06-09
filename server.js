const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const port = 3000;

// إعداد اتصال قاعدة البيانات (غيرر رابط الاتصال حسب إعدادك)
const pool = new Pool({
  connectionString: 'postgresql://username:password@localhost:5432/storedb'
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// إعداد جلسات التخزين
app.use(session({
  secret: 'secret_key_4store',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 3600000 } // 1 ساعة
}));

// توجيه لملفات الواجهة
app.use(express.static(path.join(__dirname, 'public')));

// تسجيل مستخدم جديد
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.json({ success: false, message: 'جميع الحقول مطلوبة.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    // تحقق إذا الإيميل موجود مسبقاً
    const userExist = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExist.rows.length > 0) {
      return res.json({ success: false, message: 'هذا البريد الإلكتروني مستخدم مسبقاً.' });
    }

    await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3)',
      [name, email, hashedPassword]
    );
    res.json({ success: true, message: 'تم إنشاء الحساب بنجاح، يمكنك تسجيل الدخول الآن.' });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: 'حدث خطأ أثناء إنشاء الحساب.' });
  }
});

// تسجيل الدخول
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.json({ success: false, message: 'جميع الحقول مطلوبة.' });
  }

  try {
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.json({ success: false, message: 'الإيميل غير صحيح.' });
    }

    const user = userResult.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.json({ success: false, message: 'كلمة المرور غير صحيحة.' });
    }

    // حفظ بيانات المستخدم في الجلسة
    req.session.userId = user.id;
    req.session.userName = user.name;

    res.json({ success: true, message: 'تم تسجيل الدخول بنجاح.' });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: 'حدث خطأ أثناء تسجيل الدخول.' });
  }
});

// حماية صفحة لوحة التحكم
app.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login.html');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// تسجيل خروج
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.json({ success: false, message: 'حدث خطأ أثناء تسجيل الخروج.' });
    }
    res.json({ success: true, message: 'تم تسجيل الخروج.' });
  });
});

// بدء السيرفر
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
