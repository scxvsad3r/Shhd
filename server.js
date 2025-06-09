const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret_key_very_secure';

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public')); // يخدم ملفات HTML, CSS, JS في مجلد public

// تسجيل مستخدم جديد
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.json({ success: false, message: 'يرجى تعبئة جميع الحقول' });
    }

    // تحقق إذا المستخدم موجود
    const existingUser = await db.findUserByEmail(email);
    if (existingUser) {
      return res.json({ success: false, message: 'البريد الإلكتروني مستخدم مسبقًا' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.addUser(name, email, hashedPassword);
    res.json({ success: true, message: 'تم إنشاء الحساب بنجاح!' });
  } catch (error) {
    console.error(error);
    res.json({ success: false, message: 'حدث خطأ أثناء التسجيل' });
  }
});

// تسجيل دخول
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.json({ success: false, message: 'يرجى تعبئة جميع الحقول' });
    }

    const user = await db.findUserByEmail(email);
    if (!user) {
      return res.json({ success: false, message: 'البريد الإلكتروني أو كلمة المرور خاطئة' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.json({ success: false, message: 'البريد الإلكتروني أو كلمة المرور خاطئة' });
    }

    // إنشاء JWT
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '2h' });

    // إرسال الكوكي مع التوكن (httpOnly)
    res.cookie('token', token, { httpOnly: true, maxAge: 2 * 60 * 60 * 1000 });
    res.json({ success: true, message: 'تم تسجيل الدخول بنجاح' });
  } catch (error) {
    console.error(error);
    res.json({ success: false, message: 'حدث خطأ أثناء تسجيل الدخول' });
  }
});

// ميدلوير للتحقق من التوكن
function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'غير مصرح' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'التوكن غير صالح' });
    req.user = decoded;
    next();
  });
}

// صفحة لوحة التحكم (API)
app.get('/dashboard', authMiddleware, (req, res) => {
  res.json({ message: `مرحبا ${req.user.name} في لوحة التحكم` });
});

// تسجيل خروج
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'تم تسجيل الخروج' });
});

// بدء السيرفر
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
