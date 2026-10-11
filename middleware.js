const crypto = require('crypto');

// ---------- CSRF (synchronizer token เก็บใน session) ----------
function csrf(req, res, next) {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString('hex');
  res.locals.csrfToken = req.session.csrf;

  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  const sent = String((req.body && req.body._csrf) || '');
  const real = req.session.csrf;
  const ok =
    sent.length === real.length &&
    crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(real));
  if (!ok) {
    return res.status(403).render('error', {
      title: 'คำขอไม่ถูกต้อง',
      message: 'โทเคน CSRF ไม่ถูกต้องหรือหมดอายุ กรุณากลับไปโหลดหน้าฟอร์มใหม่แล้วลองอีกครั้ง',
    });
  }
  next();
}

// ---------- flash message ----------
function flash(req, res, next) {
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
}

// ---------- Authentication / Authorization ----------
function requireAuth(req, res, next) {
  if (!req.user) {
    req.session.flash = { type: 'error', text: 'กรุณาเข้าสู่ระบบก่อน' };
    return res.redirect('/login');
  }
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.redirect('/login');
    if (req.user.role !== role) return forbidden(res);
    next();
  };
}

function forbidden(res) {
  return res.status(403).render('error', {
    title: 'ไม่มีสิทธิ์เข้าถึง',
    message: 'คุณไม่มีสิทธิ์ทำรายการนี้',
  });
}

function notFound(res) {
  return res.status(404).render('error', {
    title: 'ไม่พบข้อมูล',
    message: 'ไม่พบหน้าหรือข้อมูลที่ต้องการ',
  });
}

// แปลง :id ให้เป็นจำนวนเต็มบวก ไม่งั้น null
function toId(v) {
  return /^\d{1,9}$/.test(String(v)) ? parseInt(v, 10) : null;
}

module.exports = { csrf, flash, requireAuth, requireRole, forbidden, notFound, toId };
