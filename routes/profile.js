// ฟอร์มที่ 3 และ 4: แก้ไขโปรไฟล์ / เปลี่ยนรหัสผ่าน
const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { requireAuth } = require('../middleware');

const router = express.Router();
router.use(requireAuth);

const updateProfile = db.prepare('UPDATE users SET display_name = ?, bio = ? WHERE id = ?');
const getHash = db.prepare('SELECT password_hash FROM users WHERE id = ?');
const setHash = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?');

function render(res, extra = {}) {
  res.render('profile', { title: 'โปรไฟล์ของฉัน', profileErrors: [], pwErrors: [], ...extra });
}

router.get('/', (req, res) => render(res));

router.post('/', (req, res) => {
  const display_name = String(req.body.display_name || '').trim();
  const bio = String(req.body.bio || '').trim();
  const errors = [];
  if (display_name.length > 50) errors.push('ชื่อที่แสดงต้องไม่เกิน 50 ตัวอักษร');
  if (bio.length > 300) errors.push('คำอธิบายต้องไม่เกิน 300 ตัวอักษร');
  if (errors.length) return res.status(400).render('profile', { title: 'โปรไฟล์ของฉัน', profileErrors: errors, pwErrors: [] });
  updateProfile.run(display_name, bio, req.user.id);
  req.session.flash = { type: 'ok', text: 'บันทึกโปรไฟล์แล้ว' };
  res.redirect('/profile');
});

router.post('/password', async (req, res, next) => {
  try {
    const current = String(req.body.current || '');
    const next_ = String(req.body.password || '');
    const confirm = String(req.body.confirm || '');
    const errors = [];
    const row = getHash.get(req.user.id);
    if (!(await bcrypt.compare(current, row.password_hash))) errors.push('รหัสผ่านปัจจุบันไม่ถูกต้อง');
    if (next_.length < 8 || Buffer.byteLength(next_) > 72) errors.push('รหัสผ่านใหม่ต้องยาว 8–72 ตัวอักษร');
    if (!/[A-Za-z]/.test(next_) || !/\d/.test(next_)) errors.push('รหัสผ่านใหม่ต้องมีทั้งตัวอักษรและตัวเลข');
    if (next_ !== confirm) errors.push('รหัสผ่านใหม่และการยืนยันไม่ตรงกัน');
    if (errors.length) return res.status(400).render('profile', { title: 'โปรไฟล์ของฉัน', profileErrors: [], pwErrors: errors });
    setHash.run(await bcrypt.hash(next_, 12), req.user.id);
    req.session.flash = { type: 'ok', text: 'เปลี่ยนรหัสผ่านแล้ว' };
    res.redirect('/profile');
  } catch (e) { next(e); }
});

module.exports = router;
