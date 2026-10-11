# บอร์ดชุมชน (Secure Board) — Node.js + Express + SQLite

## รันในเครื่อง
```bash
npm install
ADMIN_PASSWORD='ตั้งเอง123' npm start     # เปิด http://localhost:3000
```
ถ้าไม่ตั้ง `ADMIN_PASSWORD` ระบบจะสุ่มรหัสแล้วพิมพ์ใน console ตอนเริ่มครั้งแรก
(Windows PowerShell: `$env:ADMIN_PASSWORD="ตั้งเอง123"; npm start`)

## เอาขึ้นโฮส (Render.com ฟรี — ทำทันในวันเดียว)
1. สร้าง repo บน GitHub แล้ว push โค้ดทั้งโฟลเดอร์ (ไม่ต้อง push `node_modules` — มี .gitignore แล้ว)
2. Render → **New → Web Service** → เลือก repo
3. Build Command: `npm install`  |  Start Command: `npm start`
4. Environment Variables:
   - `NODE_ENV` = `production`
   - `SESSION_SECRET` = สตริงสุ่มยาวๆ (Render มีปุ่ม Generate)
   - `ADMIN_PASSWORD` = รหัสผ่านแอดมินที่ตั้งเอง
5. Deploy เสร็จจะได้ลิงก์ `https://xxxx.onrender.com` → ส่งใน Classroom
6. ทดสอบ: สมัครสมาชิก 2 บัญชี, ล็อกอิน admin ที่ `/login`

หมายเหตุ: ดิสก์ของ Render แพ็กเกจฟรีเป็นแบบชั่วคราว ข้อมูล SQLite จะหายเมื่อบริการ restart/deploy ใหม่
(ระบบสร้างบัญชี admin ให้ใหม่อัตโนมัติจาก env) ถ้าต้องการให้ข้อมูลอยู่ถาวรให้เพิ่ม Persistent Disk แล้วตั้ง `DB_PATH=/var/data/app.db`
บริการฟรีจะ "หลับ" เมื่อไม่มีคนเข้า ครั้งแรกที่เปิดอาจรอ ~30–60 วินาที — **เปิดทดสอบก่อนวันตรวจ**

## ตรงกับเกณฑ์ข้อไหน
| ข้อกำหนด | ทำที่ไหน |
|---|---|
| 1. สมัคร/ล็อกอิน + hash | `routes/auth.js` — bcrypt cost 12 (ไม่เก็บรหัสผ่านจริง) |
| 2. 2 บทบาท | `user` / `admin` — `requireRole('admin')` ใน `middleware.js` |
| 3. CRUD มีเจ้าของ | `routes/posts.js` — แก้ได้เฉพาะเจ้าของ, ลบได้เจ้าของหรือ admin |
| 4. ฟอร์ม ≥ 2 | สร้าง/แก้โพสต์, คอมเมนต์, แก้โปรไฟล์, เปลี่ยนรหัสผ่าน (บันทึกลง DB แล้วแสดงผล) |
| 5. หน้า admin | `/admin` — สถิติ, จัดการผู้ใช้ (เปลี่ยน role/ลบ), ลบโพสต์ |

## การป้องกันการโจมตี (ไว้ตอบในห้อง)
| การโจมตี | วิธีป้องกัน | ไฟล์ |
|---|---|---|
| SQL Injection | prepared statements (`?`) ทุกคำสั่ง ไม่ต่อสตริง SQL | `routes/*.js` |
| XSS | EJS escape `<%= %>` ทุกจุด + CSP `script-src 'self'` ไม่มี inline script | `views/`, `server.js` |
| CSRF | token สุ่มต่อ session ใส่ทุกฟอร์ม POST + cookie `SameSite=Lax` | `middleware.js` |
| IDOR / ข้ามสิทธิ์ | เช็ก `post.user_id === req.user.id` ฝั่งเซิร์ฟเวอร์ + `WHERE id=? AND user_id=?` | `routes/posts.js` |
| Privilege escalation | role ไม่รับจากฟอร์ม, สมัครได้เป็น user เท่านั้น, `/admin` เช็ก role จาก DB ทุกคำขอ | `routes/auth.js`, `admin.js` |
| Brute force | rate limit 10 ครั้ง/15 นาที ที่ `/login` + จำกัดรวมทั้งเว็บ | `routes/auth.js`, `server.js` |
| User enumeration / timing | ข้อความ error เดียวกัน + เทียบ hash หลอกเมื่อไม่พบผู้ใช้ | `routes/auth.js` |
| Session fixation / hijack | `regenerate()` หลังล็อกอิน, cookie `httpOnly` + `secure` + หมดอายุ 2 ชม. | `server.js` |
| Clickjacking / sniffing | Helmet: `frame-ancestors 'none'`, `nosniff`, HSTS | `server.js` |
| DoS ขนาดใหญ่ | จำกัด body 20 KB, จำกัดความยาวทุกช่อง | `server.js` |
| ข้อมูลรั่ว | หน้า error ไม่แสดง stack trace, ปิด `x-powered-by` | `server.js` |

## คำถามที่อาจโดนถามบ่อย
- **ทำไมใช้ bcrypt ไม่ใช้ MD5/SHA256?** แฮชเร็วถูกเดาได้เป็นพันล้านครั้ง/วินาที bcrypt ช้าโดยตั้งใจ (cost 12) และมี salt ในตัว
- **Salt คืออะไร?** ค่าสุ่มผสมก่อนแฮช ทำให้รหัสเดียวกันได้แฮชต่างกัน กัน rainbow table — bcrypt สร้างและเก็บไว้ในสตริงแฮชให้เอง
- **Authentication vs Authorization?** ยืนยันว่าคุณคือใคร (ล็อกอิน) vs ตรวจว่าคุณทำอะไรได้ (role / เจ้าของ)
- **IDOR คืออะไร?** แก้ id ใน URL เพื่อเข้าถึงข้อมูลคนอื่น — กันด้วยเช็กความเป็นเจ้าของฝั่งเซิร์ฟเวอร์ทุกครั้ง
- **CSRF คืออะไร?** เว็บอื่นหลอกให้เบราว์เซอร์ที่ล็อกอินอยู่ส่งคำขอมาที่เว็บเรา — กันด้วย token ที่เว็บอื่นเดาไม่ได้
- **Session ทำงานอย่างไร?** เซิร์ฟเวอร์เก็บข้อมูลใน DB (ตาราง `sessions`) cookie เก็บแค่ id ที่เซ็นลายเซ็น
- **ทำไม admin แก้โพสต์คนอื่นไม่ได้?** admin ลบเพื่อดูแลเนื้อหาได้ แต่ไม่แก้เนื้อหาแทนเจ้าของ (least privilege)
- **ถ้าอยากเดโมการโจมตี:** ใส่ `<script>alert(1)</script>` ในโพสต์ (แสดงเป็นข้อความ), ใส่ `' OR '1'='1` ในช่องล็อกอิน (ล็อกอินไม่ได้), ลองเปิด `/posts/1/edit` ของคนอื่น (403), ลองเข้า `/admin` ด้วย user (403)
