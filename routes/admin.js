const express = require('express');
const db = require('../db');
const { requireRole, notFound, toId } = require('../middleware');

const router = express.Router();
router.use(requireRole('admin'));        // ทุกเส้นทางใต้ /admin ต้องเป็น admin

const q = {
  stats: db.prepare(`SELECT (SELECT COUNT(*) FROM users) AS users,
                            (SELECT COUNT(*) FROM users WHERE role='admin') AS admins,
                            (SELECT COUNT(*) FROM posts) AS posts,
                            (SELECT COUNT(*) FROM comments) AS comments`),
  users: db.prepare(`SELECT u.id, u.username, u.email, u.role, u.created_at,
                            (SELECT COUNT(*) FROM posts p WHERE p.user_id = u.id) AS post_count
                     FROM users u ORDER BY u.id`),
  posts: db.prepare(`SELECT p.id, p.title, p.created_at, u.username FROM posts p
                     JOIN users u ON u.id = p.user_id ORDER BY p.id DESC LIMIT 50`),
  user: db.prepare('SELECT id, role FROM users WHERE id = ?'),
  setRole: db.prepare('UPDATE users SET role = ? WHERE id = ?'),
  delUser: db.prepare('DELETE FROM users WHERE id = ?'),
};

router.get('/', (req, res) => {
  res.render('admin', { title: 'จัดการระบบ', stats: q.stats.get(), users: q.users.all(), posts: q.posts.all() });
});

router.post('/users/:id/role', (req, res) => {
  const id = toId(req.params.id);
  const target = id && q.user.get(id);
  if (!target) return notFound(res);
  const role = String(req.body.role);
  if (!['user', 'admin'].includes(role)) {            // whitelist
    req.session.flash = { type: 'error', text: 'บทบาทไม่ถูกต้อง' };
    return res.redirect('/admin');
  }
  if (id === req.user.id) {
    req.session.flash = { type: 'error', text: 'ไม่สามารถเปลี่ยนบทบาทของตัวเองได้' };
    return res.redirect('/admin');
  }
  q.setRole.run(role, id);
  req.session.flash = { type: 'ok', text: 'เปลี่ยนบทบาทแล้ว' };
  res.redirect('/admin');
});

router.post('/users/:id/delete', (req, res) => {
  const id = toId(req.params.id);
  if (!id || !q.user.get(id)) return notFound(res);
  if (id === req.user.id) {
    req.session.flash = { type: 'error', text: 'ไม่สามารถลบบัญชีของตัวเองได้' };
    return res.redirect('/admin');
  }
  q.delUser.run(id);   // โพสต์/คอมเมนต์ของผู้ใช้ถูกลบตาม (ON DELETE CASCADE)
  req.session.flash = { type: 'ok', text: 'ลบผู้ใช้แล้ว' };
  res.redirect('/admin');
});

module.exports = router;
