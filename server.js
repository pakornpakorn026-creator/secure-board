const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

const db = require('./db');
const SqliteStore = require('./sessionStore');
const { csrf, flash, notFound } = require('./middleware');

const isProd = process.env.NODE_ENV === 'production';
const app = express();

// helper แสดงวันที่ (เวลา SQLite เป็น UTC)
app.locals.fmt = (s) =>
  new Date(String(s).replace(' ', 'T') + 'Z').toLocaleString('th-TH', {
    timeZone: 'Asia/Bangkok', dateStyle: 'medium', timeStyle: 'short',
  });

// อยู่หลัง proxy ของโฮสต์ (Render/Railway ฯลฯ) เพื่อให้ cookie secure และ rate-limit ทำงานถูก
app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.disable('x-powered-by');

// ---------- Security headers (Helmet + CSP) ----------
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],          // ห้าม inline script -> กัน XSS
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],     // กัน clickjacking
      },
    },
  })
);

// ---------- Rate limit ทั้งเว็บ ----------
app.use(rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false }));

// ---------- Body parsing (จำกัดขนาด) ----------
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));

// ---------- Session ----------
let secret = process.env.SESSION_SECRET;
if (!secret) {
  if (isProd) {
    console.error('ต้องตั้งค่า SESSION_SECRET ใน production');
    process.exit(1);
  }
  secret = 'dev-only-secret-change-me';
}
app.use(
  session({
    name: 'sid',
    secret,
    resave: false,
    saveUninitialized: false,
    store: new SqliteStore(db),
    cookie: {
      httpOnly: true,                 // JS อ่าน cookie ไม่ได้
      sameSite: 'lax',                // ช่วยกัน CSRF
      secure: isProd,                 // ส่งเฉพาะ HTTPS ตอนขึ้นโฮสต์
      maxAge: 2 * 60 * 60 * 1000,     // 2 ชั่วโมง
    },
  })
);

// โหลดผู้ใช้ปัจจุบันจาก DB ทุกคำขอ (ถ้าถูกลบ/เปลี่ยน role จะมีผลทันที)
const getUser = db.prepare('SELECT id, username, email, role, display_name, bio FROM users WHERE id = ?');
app.use((req, res, next) => {
  req.user = req.session.userId ? getUser.get(req.session.userId) || null : null;
  if (!req.user && req.session.userId) delete req.session.userId;
  res.locals.currentUser = req.user;
  res.locals.path = req.path;
  next();
});

app.use(flash);   // ต้องมาก่อน csrf เพื่อให้หน้า error 403 มีตัวแปร flash
app.use(csrf);

// ---------- Routes ----------
app.get('/', (req, res) => res.render('home', { title: 'หน้าแรก' }));
app.use(require('./routes/auth'));
app.use('/posts', require('./routes/posts'));
app.use(require('./routes/comments'));
app.use('/profile', require('./routes/profile'));
app.use('/admin', require('./routes/admin'));

// ---------- 404 / error handler ----------
app.use((req, res) => notFound(res));
app.use((err, req, res, next) => {
  console.error(err);                   // log ฝั่งเซิร์ฟเวอร์เท่านั้น ไม่ส่ง stack ให้ผู้ใช้
  res.status(500).render('error', { title: 'เกิดข้อผิดพลาด', message: 'ระบบขัดข้อง กรุณาลองใหม่ภายหลัง' });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
