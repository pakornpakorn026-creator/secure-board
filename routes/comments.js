// ฟอร์มที่ 2: ความคิดเห็นใต้โพสต์ (บันทึกลง DB แล้วแสดงผลกลับ)
const express = require('express');
const db = require('../db');
const { requireAuth, forbidden, notFound, toId } = require('../middleware');

const router = express.Router();
router.use(requireAuth);

const getPost = db.prepare('SELECT id FROM posts WHERE id = ?');
const getComment = db.prepare('SELECT * FROM comments WHERE id = ?');
const insert = db.prepare('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)');
const remove = db.prepare('DELETE FROM comments WHERE id = ?');

router.post('/posts/:id/comments', (req, res) => {
  const postId = toId(req.params.id);
  if (!postId || !getPost.get(postId)) return notFound(res);
  const content = String(req.body.content || '').trim();
  if (content.length < 1 || content.length > 500) {
    req.session.flash = { type: 'error', text: 'ความคิดเห็นต้องยาว 1–500 ตัวอักษร' };
    return res.redirect(`/posts/${postId}`);
  }
  insert.run(postId, req.user.id, content);
  req.session.flash = { type: 'ok', text: 'เพิ่มความคิดเห็นแล้ว' };
  res.redirect(`/posts/${postId}#comments`);
});

router.post('/comments/:id/delete', (req, res) => {
  const id = toId(req.params.id);
  const c = id && getComment.get(id);
  if (!c) return notFound(res);
  if (c.user_id !== req.user.id && req.user.role !== 'admin') return forbidden(res);
  remove.run(id);
  req.session.flash = { type: 'ok', text: 'ลบความคิดเห็นแล้ว' };
  res.redirect(`/posts/${c.post_id}#comments`);
});

module.exports = router;
