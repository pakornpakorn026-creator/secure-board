// ไม่มี inline script (CSP script-src 'self') จึงผูก event ที่นี่
document.addEventListener('submit', function (e) {
  var msg = e.target.getAttribute && e.target.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) e.preventDefault();
});
