const express = require('express');
const db = require('../db');
const { requireAuth, forbidden, notFound, toId } = require('../middleware');

const router = express.Router();
router.use(requireAuth);

const q = {
  list: db.prepare(`SELECT p.id, p.title, p.content, p.created_at, p.user_id, u.username,
                           (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
                    FROM posts p JOIN users u ON u.id = p.user_id
                    ORDER BY p.id DESC LIMIT 100`),
  mine: db.prepare(`SELECT p.id, p.title, p.content, p.created_at, p.user_id, u.username,
                           (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
                    FROM posts p JOIN users u ON u.id = p.user_id
                    WHERE p.user_id = ? ORDER BY p.id DESC LIMIT 100`),
  one: db.prepare(`SELECT p.*, u.username FROM posts p JOIN users u ON u.id = p.user_id WHERE p.id = ?`),
  comments: db.prepare(`SELECT c.id, c.content, c.created_at, c.user_id, u.username
                        FROM comments c JOIN users u ON u.id = c.user_id
                        WHERE c.post_id = ? ORDER BY c.id ASC`),
  insert: db.prepare('INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)'),
  update: db.prepare("UPDATE posts SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?"),
  remove: db.prepare('DELETE FROM posts WHERE id = ?'),
};

function validate(body) {
  const title = String(body.title || '').trim();
  const content = String(body.content || '').trim();
  const errors = [];
  if (title.length < 3 || title.length > 100) errors.push('หัวข้อต้องยาว 3–100 ตัวอักษร');
  if (content.length < 3 || content.length > 2000) errors.push('เนื้อหาต้องยาว 3–2000 ตัวอักษร');
  return { title, content, errors };
}

// READ (list) — ?mine=1 เพื่อดูเฉพาะของตัวเอง
router.get('/', (req, res) => {
  const mine = req.query.mine === '1';
  const posts = mine ? q.mine.all(req.user.id) : q.list.all();
  res.render('posts/index', { title: mine ? 'โพสต์ของฉัน' : 'บอร์ดทั้งหมด', posts, mine });
});

// CREATE
router.get('/new', (req, res) => {
  res.render('posts/form', { title: 'เขียนโพสต์ใหม่', post: {}, errors: [], action: '/posts' });
});

router.post('/', (req, res) => {
  const { title, content, errors } = validate(req.body);
  if (errors.length) {
    return res.status(400).render('posts/form', { title: 'เขียนโพสต์ใหม่', post: { title, content }, errors, action: '/posts' });
  }
  const info = q.insert.run(req.user.id, title, content);   // user_id มาจาก session เสมอ ไม่รับจากฟอร์ม
  req.session.flash = { type: 'ok', text: 'บันทึกโพสต์แล้ว' };
  res.redirect(`/posts/${info.lastInsertRowid}`);
});

// READ (one)
router.get('/:id', (req, res) => {
  const id = toId(req.params.id);
  const post = id && q.one.get(id);
  if (!post) return notFound(res);
  res.render('posts/show', { title: post.title, post, comments: q.comments.all(id), errors: [] });
});

// UPDATE — เจ้าของเท่านั้น (admin ก็แก้ของคนอื่นไม่ได้)
router.get('/:id/edit', (req, res) => {
  const id = toId(req.params.id);
  const post = id && q.one.get(id);
  if (!post) return notFound(res);
  if (post.user_id !== req.user.id) return forbidden(res);
  res.render('posts/form', { title: 'แก้ไขโพสต์', post, errors: [], action: `/posts/${id}/edit` });
});

router.post('/:id/edit', (req, res) => {
  const id = toId(req.params.id);
  const post = id && q.one.get(id);
  if (!post) return notFound(res);
  if (post.user_id !== req.user.id) return forbidden(res);       // กัน IDOR
  const { title, content, errors } = validate(req.body);
  if (errors.length) {
    return res.status(400).render('posts/form', { title: 'แก้ไขโพสต์', post: { id, title, content }, errors, action: `/posts/${id}/edit` });
  }
  q.update.run(title, content, id, req.user.id);                 // WHERE ... AND user_id = ? อีกชั้น
  req.session.flash = { type: 'ok', text: 'แก้ไขโพสต์แล้ว' };
  res.redirect(`/posts/${id}`);
});

// DELETE — เจ้าของ หรือ admin (ดูแลเนื้อหา)
router.post('/:id/delete', (req, res) => {
  const id = toId(req.params.id);
  const post = id && q.one.get(id);
  if (!post) return notFound(res);
  if (post.user_id !== req.user.id && req.user.role !== 'admin') return forbidden(res);
  q.remove.run(id);
  req.session.flash = { type: 'ok', text: 'ลบโพสต์แล้ว' };
  res.redirect('/posts');
});

module.exports = router;
