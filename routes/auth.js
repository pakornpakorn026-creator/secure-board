const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const db = require('../db');

const router = express.Router();
const BCRYPT_COST = 12;
// hash หลอก ไว้เทียบเวลาเมื่อไม่พบผู้ใช้ (กัน timing attack เดาชื่อผู้ใช้)
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', BCRYPT_COST);

// จำกัดการเดารหัสผ่าน: 10 ครั้ง / 15 นาที / IP (นับเฉพาะที่ล้มเหลว)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  skipSuccessfulRequests: true,
  handler: (req, res) => {
    res.status(429).render('error', {
      title: 'ลองมากเกินไป',
      message: 'พยายามเข้าสู่ระบบผิดหลายครั้ง กรุณารอ 15 นาทีแล้วลองใหม่',
    });
  },
});
const registerLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 20 });

const findUser = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?');
const insertUser = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)');

function validateRegister({ username, email, password, confirm }) {
  const errors = [];
  if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) errors.push('ชื่อผู้ใช้ต้องเป็น a-z, 0-9, _ ความยาว 3–20 ตัวอักษร');
  if (!/^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/.test(email) || email.length > 120) errors.push('รูปแบบอีเมลไม่ถูกต้อง');
  if (password.length < 8) errors.push('รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร');
  if (Buffer.byteLength(password) > 72) errors.push('รหัสผ่านยาวเกินไป (สูงสุด 72 ไบต์)');
  if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) errors.push('รหัสผ่านต้องมีทั้งตัวอักษรและตัวเลข');
  if (password !== confirm) errors.push('รหัสผ่านและการยืนยันไม่ตรงกัน');
  return errors;
}

router.get('/register', (req, res) => {
  if (req.user) return res.redirect('/posts');
  res.render('register', { title: 'สมัครสมาชิก', errors: [], values: {} });
});

router.post('/register', registerLimiter, async (req, res, next) => {
  try {
    const username = String(req.body.username || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const confirm = String(req.body.confirm || '');

    const errors = validateRegister({ username, email, password, confirm });
    if (!errors.length && findUser.get(username, email)) errors.push('ชื่อผู้ใช้หรืออีเมลนี้ถูกใช้แล้ว');
    if (errors.length) {
      return res.status(400).render('register', { title: 'สมัครสมาชิก', errors, values: { username, email } });
    }

    const hash = await bcrypt.hash(password, BCRYPT_COST);
    // role ไม่รับจากฟอร์มเด็ดขาด -> ทุกคนที่สมัครเป็น 'user' (กัน mass assignment)
    insertUser.run(username, email, hash);

    req.session.flash = { type: 'ok', text: 'สมัครสมาชิกสำเร็จ กรุณาเข้าสู่ระบบ' };
    res.redirect('/login');
  } catch (e) {
    if (String(e.code).startsWith('SQLITE_CONSTRAINT')) {
      return res.status(400).render('register', {
        title: 'สมัครสมาชิก', errors: ['ชื่อผู้ใช้หรืออีเมลนี้ถูกใช้แล้ว'], values: {},
      });
    }
    next(e);
  }
});

router.get('/login', (req, res) => {
  if (req.user) return res.redirect('/posts');
  res.render('login', { title: 'เข้าสู่ระบบ', error: null });
});

router.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const login = String(req.body.login || '').trim().slice(0, 120);
    const password = String(req.body.password || '').slice(0, 200);

    const user = findUser.get(login, login.toLowerCase());
    const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);

    if (!user || !ok) {
      // ข้อความเดียวกันเสมอ ไม่บอกว่าผิดที่ชื่อหรือรหัส
      return res.status(401).render('login', { title: 'เข้าสู่ระบบ', error: 'ชื่อผู้ใช้/อีเมล หรือรหัสผ่านไม่ถูกต้อง' });
    }

    // สร้าง session ใหม่หลังล็อกอิน (กัน session fixation)
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id;
      req.session.flash = { type: 'ok', text: `ยินดีต้อนรับ ${user.username}` };
      res.redirect('/posts');
    });
  } catch (e) { next(e); }
});

router.post('/logout', (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('sid');
    res.redirect('/');
  });
});

module.exports = router;
