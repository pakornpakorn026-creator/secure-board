// Session store เก็บใน SQLite (ไม่ใช้ MemoryStore ที่ไม่เหมาะกับ production)
const session = require('express-session');

class SqliteStore extends session.Store {
  constructor(db) {
    super();
    this.db = db;
    this.q = {
      get: db.prepare('SELECT data FROM sessions WHERE sid = ? AND expires > ?'),
      set: db.prepare('INSERT OR REPLACE INTO sessions (sid, data, expires) VALUES (?, ?, ?)'),
      del: db.prepare('DELETE FROM sessions WHERE sid = ?'),
      touch: db.prepare('UPDATE sessions SET expires = ? WHERE sid = ?'),
      clean: db.prepare('DELETE FROM sessions WHERE expires <= ?'),
    };
    setInterval(() => this.q.clean.run(Date.now()), 15 * 60 * 1000).unref();
  }
  _exp(sess) {
    return sess && sess.cookie && sess.cookie.expires
      ? new Date(sess.cookie.expires).getTime()
      : Date.now() + 2 * 3600 * 1000;
  }
  get(sid, cb) {
    try {
      const row = this.q.get.get(sid, Date.now());
      cb(null, row ? JSON.parse(row.data) : null);
    } catch (e) { cb(e); }
  }
  set(sid, sess, cb) {
    try { this.q.set.run(sid, JSON.stringify(sess), this._exp(sess)); cb && cb(null); }
    catch (e) { cb && cb(e); }
  }
  destroy(sid, cb) {
    try { this.q.del.run(sid); cb && cb(null); } catch (e) { cb && cb(e); }
  }
  touch(sid, sess, cb) {
    try { this.q.touch.run(this._exp(sess), sid); cb && cb(null); } catch (e) { cb && cb(e); }
  }
}
module.exports = SqliteStore;
