// server.js — Backend cho "Hải Đăng Sức Khỏe": Chatbot AI (Gemini) + Đăng nhập/Phân quyền + Yêu cầu/Vật tư
//
// Vai trò:
//  - admin:   quản trị tài khoản (duyệt, đổi vai trò, khóa/mở), xem toàn bộ hệ thống
//  - citizen: người dân — dùng Hồ sơ sức khỏe, Chăm sóc sức khỏe, Trợ lý AI, gửi yêu cầu/phản ánh
//  - medical: nhân viên y tế — tiếp nhận yêu cầu/phản ánh từ người dân, đề nghị cung cấp vật tư
//
// Dữ liệu lưu trong file db.json trên server (đơn giản, phù hợp demo/đồ án).
// LƯU Ý: trên Render free tier, dữ liệu sẽ bị làm mới mỗi khi deploy lại (đọc kỹ README).

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = 'gemini-3.5-flash-lite';
const JWT_SECRET = process.env.JWT_SECRET || 'hai-dang-suc-khoe-secret-doi-ngay-khi-deploy-that';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@haidang.vn';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin@123';

// ---------------------------------------------------------------------------
// Lưu trữ dữ liệu đơn giản bằng file JSON
// ---------------------------------------------------------------------------
const DB_PATH = path.join(__dirname, 'db.json');

function loadDb() {
  if (!fs.existsSync(DB_PATH)) {
    return { users: [], requests: [], supplyProposals: [], familyMembers: [], sosAlerts: [] };
  }
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
  } catch (e) {
    console.error('Không đọc được db.json, khởi tạo lại:', e);
    return { users: [], requests: [], supplyProposals: [], familyMembers: [], sosAlerts: [] };
  }
}
function saveDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf-8');
}

let db = loadDb();
// Migration: db.json cũ chưa có các mảng này.
if (!Array.isArray(db.familyMembers)) db.familyMembers = [];
if (!Array.isArray(db.sosAlerts)) db.sosAlerts = [];

// Seed tài khoản admin đầu tiên nếu chưa có
if (!db.users.some(u => u.role === 'admin')) {
  const passwordHash = bcrypt.hashSync(ADMIN_PASSWORD, 10);
  db.users.push({
    id: crypto.randomUUID(),
    name: 'Quản trị viên',
    email: ADMIN_EMAIL,
    passwordHash,
    role: 'admin',
    status: 'active',
    createdAt: new Date().toISOString(),
  });
  saveDb(db);
  console.log(`✅ Đã tạo tài khoản admin mặc định: ${ADMIN_EMAIL} — nhớ đổi mật khẩu sau khi đăng nhập lần đầu.`);
}

function publicUser(u) {
  const { passwordHash, ...rest } = u;
  return rest;
}

// ---------------------------------------------------------------------------
// Middleware xác thực
// ---------------------------------------------------------------------------
function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Chưa đăng nhập.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.users.find(u => u.id === payload.id);
    if (!user) return res.status(401).json({ error: 'Tài khoản không tồn tại.' });
    if (user.status !== 'active') return res.status(403).json({ error: 'Tài khoản chưa được kích hoạt hoặc đã bị khóa.' });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Phiên đăng nhập không hợp lệ hoặc đã hết hạn.' });
  }
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Bạn không có quyền thực hiện thao tác này.' });
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// AUTH: đăng ký / đăng nhập / thông tin cá nhân
// ---------------------------------------------------------------------------
app.post('/api/auth/register', (req, res) => {
  const { name, email, password, role } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Vui lòng điền đầy đủ họ tên, email và mật khẩu.' });
  }
  if (!['citizen', 'medical'].includes(role)) {
    return res.status(400).json({ error: 'Vai trò đăng ký không hợp lệ.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Mật khẩu cần tối thiểu 6 ký tự.' });
  }
  const emailLower = String(email).toLowerCase().trim();
  if (db.users.some(u => u.email.toLowerCase() === emailLower)) {
    return res.status(409).json({ error: 'Email này đã được đăng ký.' });
  }

  const user = {
    id: crypto.randomUUID(),
    name: String(name).trim(),
    email: emailLower,
    passwordHash: bcrypt.hashSync(password, 10),
    role,
    // Người dân được kích hoạt ngay; nhân viên y tế cần admin duyệt trước khi đăng nhập được.
    status: role === 'citizen' ? 'active' : 'pending',
    createdAt: new Date().toISOString(),
  };
  db.users.push(user);
  saveDb(db);

  if (user.status === 'pending') {
    return res.status(201).json({
      message: 'Đăng ký thành công. Tài khoản nhân viên y tế cần được quản trị viên duyệt trước khi đăng nhập được.',
      pending: true,
    });
  }

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.status(201).json({ token, user: publicUser(user) });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Vui lòng nhập email và mật khẩu.' });

  const user = db.users.find(u => u.email.toLowerCase() === String(email).toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Email hoặc mật khẩu không đúng.' });
  }
  if (user.status === 'pending') {
    return res.status(403).json({ error: 'Tài khoản đang chờ quản trị viên duyệt.' });
  }
  if (user.status === 'blocked') {
    return res.status(403).json({ error: 'Tài khoản đã bị khóa. Liên hệ quản trị viên để biết thêm.' });
  }

  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: publicUser(user) });
});

app.get('/api/auth/me', authRequired, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.patch('/api/auth/me', authRequired, (req, res) => {
  const { phone } = req.body || {};
  if (phone !== undefined) req.user.phone = String(phone).trim();
  saveDb(db);
  res.json({ user: publicUser(req.user) });
});

// ---------------------------------------------------------------------------
// ADMIN: quản lý tài khoản
// ---------------------------------------------------------------------------
app.get('/api/admin/users', authRequired, requireRole('admin'), (req, res) => {
  res.json({ users: db.users.map(publicUser) });
});

app.patch('/api/admin/users/:id', authRequired, requireRole('admin'), (req, res) => {
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Không tìm thấy người dùng.' });

  const { role, status } = req.body || {};
  if (role && ['admin', 'citizen', 'medical'].includes(role)) user.role = role;
  if (status && ['active', 'pending', 'blocked'].includes(status)) user.status = status;
  saveDb(db);
  res.json({ user: publicUser(user) });
});

// ---------------------------------------------------------------------------
// HỒ SƠ SỨC KHỎE GIA ĐÌNH (nhiều thành viên / 1 tài khoản citizen) + CẢNH BÁO RỦI RO
// ---------------------------------------------------------------------------

// Ngưỡng cảnh báo đơn giản dựa trên các chỉ số sinh hiệu phổ biến.
// Đây chỉ là ngưỡng tham khảo chung cho người trưởng thành, không thay thế tư vấn y khoa.
function checkVitalAlerts(v) {
  const alerts = [];
  if (v.bp) {
    const m = String(v.bp).match(/(\d+)\s*\/\s*(\d+)/);
    if (m) {
      const sys = parseInt(m[1], 10), dia = parseInt(m[2], 10);
      if (sys >= 140 || dia >= 90) alerts.push({ level: 'cao', message: `Huyết áp cao (${v.bp} mmHg)` });
      else if (sys > 0 && sys < 90) alerts.push({ level: 'canh_bao', message: `Huyết áp thấp (${v.bp} mmHg)` });
    }
  }
  if (v.hr) {
    const hr = Number(v.hr);
    if (hr > 100) alerts.push({ level: 'canh_bao', message: `Nhịp tim nhanh (${hr} bpm)` });
    else if (hr > 0 && hr < 60) alerts.push({ level: 'canh_bao', message: `Nhịp tim chậm (${hr} bpm)` });
  }
  if (v.sugar) {
    const s = Number(v.sugar);
    if (s >= 126) alerts.push({ level: 'cao', message: `Đường huyết cao (${s} mg/dL)` });
    else if (s > 0 && s < 70) alerts.push({ level: 'cao', message: `Đường huyết thấp (${s} mg/dL)` });
  }
  return alerts;
}

function findOwnedMember(req, res) {
  const member = db.familyMembers.find(m => m.id === req.params.id);
  if (!member) { res.status(404).json({ error: 'Không tìm thấy thành viên.' }); return null; }
  if (member.ownerId !== req.user.id) { res.status(403).json({ error: 'Bạn không có quyền với hồ sơ này.' }); return null; }
  return member;
}

// Danh sách thành viên gia đình của tài khoản đang đăng nhập
app.get('/api/family', authRequired, requireRole('citizen'), (req, res) => {
  const members = db.familyMembers.filter(m => m.ownerId === req.user.id);
  res.json({ members });
});

// Thêm thành viên mới
app.post('/api/family', authRequired, requireRole('citizen'), (req, res) => {
  const { name, relationship, dob, gender, history } = req.body || {};
  if (!name) return res.status(400).json({ error: 'Thiếu tên thành viên.' });
  const member = {
    id: crypto.randomUUID(),
    ownerId: req.user.id,
    name: String(name).trim(),
    relationship: relationship || '',
    dob: dob || '',
    gender: gender || '',
    history: history || '',
    exams: [],
    meds: [],
    vitals: [],
    createdAt: new Date().toISOString(),
  };
  db.familyMembers.push(member);
  saveDb(db);
  res.status(201).json({ member });
});

// Sửa thông tin thành viên
app.patch('/api/family/:id', authRequired, requireRole('citizen'), (req, res) => {
  const member = findOwnedMember(req, res);
  if (!member) return;
  const { name, relationship, dob, gender, history } = req.body || {};
  if (name) member.name = String(name).trim();
  if (relationship !== undefined) member.relationship = relationship;
  if (dob !== undefined) member.dob = dob;
  if (gender !== undefined) member.gender = gender;
  if (history !== undefined) member.history = history;
  saveDb(db);
  res.json({ member });
});

// Xóa thành viên
app.delete('/api/family/:id', authRequired, requireRole('citizen'), (req, res) => {
  const idx = db.familyMembers.findIndex(m => m.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Không tìm thấy thành viên.' });
  if (db.familyMembers[idx].ownerId !== req.user.id) return res.status(403).json({ error: 'Bạn không có quyền với hồ sơ này.' });
  db.familyMembers.splice(idx, 1);
  saveDb(db);
  res.json({ ok: true });
});

// Lịch sử khám của 1 thành viên
app.post('/api/family/:id/exams', authRequired, requireRole('citizen'), (req, res) => {
  const member = findOwnedMember(req, res);
  if (!member) return;
  const { date, place, note } = req.body || {};
  if (!place) return res.status(400).json({ error: 'Thiếu nơi khám.' });
  const exam = { id: crypto.randomUUID(), date: date || '', place, note: note || '' };
  member.exams.push(exam);
  saveDb(db);
  res.status(201).json({ exam });
});
app.delete('/api/family/:id/exams/:examId', authRequired, requireRole('citizen'), (req, res) => {
  const member = findOwnedMember(req, res);
  if (!member) return;
  member.exams = member.exams.filter(e => e.id !== req.params.examId);
  saveDb(db);
  res.json({ ok: true });
});

// Lịch sử dùng thuốc của 1 thành viên
app.post('/api/family/:id/meds', authRequired, requireRole('citizen'), (req, res) => {
  const member = findOwnedMember(req, res);
  if (!member) return;
  const { name, schedule } = req.body || {};
  if (!name) return res.status(400).json({ error: 'Thiếu tên thuốc.' });
  const med = { id: crypto.randomUUID(), name, schedule: schedule || '' };
  member.meds.push(med);
  saveDb(db);
  res.status(201).json({ med });
});
app.delete('/api/family/:id/meds/:medId', authRequired, requireRole('citizen'), (req, res) => {
  const member = findOwnedMember(req, res);
  if (!member) return;
  member.meds = member.meds.filter(m => m.id !== req.params.medId);
  saveDb(db);
  res.json({ ok: true });
});

// Ghi nhận chỉ số sức khỏe (huyết áp / nhịp tim / đường huyết) + trả về cảnh báo ngưỡng ngay lập tức
app.post('/api/family/:id/vitals', authRequired, requireRole('citizen'), (req, res) => {
  const member = findOwnedMember(req, res);
  if (!member) return;
  const { bp, hr, sugar } = req.body || {};
  if (!bp && !hr && !sugar) return res.status(400).json({ error: 'Cần nhập ít nhất một chỉ số.' });
  const vital = { id: crypto.randomUUID(), date: new Date().toISOString(), bp: bp || '', hr: hr || '', sugar: sugar || '' };
  const alerts = checkVitalAlerts(vital);
  member.vitals.push(vital);
  if (member.vitals.length > 30) member.vitals.shift();
  saveDb(db);
  res.status(201).json({ vital, alerts });
});

// Phân tích AI (Gemini) dựa trên hồ sơ + chỉ số gần đây + cảnh báo ngưỡng của 1 thành viên
app.post('/api/family/:id/ai-insight', authRequired, requireRole('citizen', 'admin'), async (req, res) => {
  const member = findOwnedMember(req, res);
  if (!member) return;
  if (!GEMINI_API_KEY) return res.status(500).json({ error: 'Server chưa cấu hình GEMINI_API_KEY.' });

  const latestVitals = member.vitals.slice(-5);
  const alerts = latestVitals.length ? checkVitalAlerts(latestVitals[latestVitals.length - 1]) : [];

  const prompt = `Bạn là trợ lý sức khỏe. Dưới đây là hồ sơ một thành viên gia đình:
- Tên: ${member.name} — Quan hệ: ${member.relationship || 'không rõ'} — Giới tính: ${member.gender || 'không rõ'} — Ngày sinh: ${member.dob || 'không rõ'}
- Tiền sử bệnh / dị ứng: ${member.history || 'không có'}
- Các chỉ số gần đây (mới nhất ở cuối): ${JSON.stringify(latestVitals)}
- Cảnh báo do hệ thống phát hiện dựa trên ngưỡng: ${alerts.length ? alerts.map(a => a.message).join('; ') : 'không có bất thường theo ngưỡng'}

Hãy viết nhận định ngắn gọn (3-5 câu, tiếng Việt) về tình trạng hiện tại và khuyến nghị nên làm gì tiếp theo. Nếu có dấu hiệu cần đi khám sớm thì nói rõ. Không đưa ra chẩn đoán chắc chắn, luôn nhắc nên gặp bác sĩ khi cần thiết.`;

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': GEMINI_API_KEY },
        body: JSON.stringify({ contents: [{ role: 'user', parts: [{ text: prompt }] }] }),
      }
    );
    const data = await response.json();
    if (!response.ok) {
      console.error('Gemini API error:', data);
      return res.status(response.status).json({ error: data.error?.message || 'Lỗi từ Gemini API' });
    }
    const text = data.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('') || '';
    res.json({ insight: text, alerts });
  } catch (err) {
    console.error('AI insight error:', err);
    res.status(500).json({ error: 'Không thể kết nối đến Gemini API.' });
  }
});

// ---------------------------------------------------------------------------
// SOS KHẨN CẤP + ĐỊNH VỊ GPS
// ---------------------------------------------------------------------------

// Người dân bấm nút SOS: tạo 1 cảnh báo mới kèm vị trí hiện tại + SĐT liên hệ
app.post('/api/sos', authRequired, requireRole('citizen'), (req, res) => {
  const { lat, lng, phone, note } = req.body || {};
  if (lat === undefined || lng === undefined) {
    return res.status(400).json({ error: 'Thiếu tọa độ vị trí (cần cho phép trình duyệt truy cập vị trí).' });
  }
  if (phone) req.user.phone = String(phone).trim(); // lưu lại SĐT cho lần sau
  const now = new Date().toISOString();
  const alert = {
    id: crypto.randomUUID(),
    userId: req.user.id,
    name: req.user.name,
    phone: phone || req.user.phone || '',
    note: note || '',
    status: 'active', // active -> confirmed -> resolved
    lat, lng,
    locationHistory: [{ lat, lng, at: now }],
    createdAt: now,
    updatedAt: now,
    confirmedBy: null,
  };
  db.sosAlerts.push(alert);
  saveDb(db);
  res.status(201).json({ alert });
});

// Trình duyệt của người dân tiếp tục gửi vị trí mới trong lúc chờ xe cấp cứu
app.patch('/api/sos/:id/location', authRequired, requireRole('citizen'), (req, res) => {
  const alert = db.sosAlerts.find(a => a.id === req.params.id);
  if (!alert) return res.status(404).json({ error: 'Không tìm thấy cảnh báo SOS.' });
  if (alert.userId !== req.user.id) return res.status(403).json({ error: 'Không có quyền với cảnh báo này.' });
  if (alert.status === 'resolved') return res.status(400).json({ error: 'Cảnh báo này đã được xử lý xong.' });
  const { lat, lng } = req.body || {};
  if (lat === undefined || lng === undefined) return res.status(400).json({ error: 'Thiếu tọa độ.' });
  alert.lat = lat; alert.lng = lng;
  alert.updatedAt = new Date().toISOString();
  alert.locationHistory.push({ lat, lng, at: alert.updatedAt });
  if (alert.locationHistory.length > 100) alert.locationHistory.shift();
  saveDb(db);
  res.json({ alert });
});

// Người dân tự kiểm tra trạng thái cảnh báo SOS của chính mình (đang chờ / đã xác nhận)
app.get('/api/sos/mine', authRequired, requireRole('citizen'), (req, res) => {
  const alert = [...db.sosAlerts].reverse().find(a => a.userId === req.user.id && a.status !== 'resolved');
  res.json({ alert: alert || null });
});

// Người dân hủy / đánh dấu đã ổn (tự đóng cảnh báo)
app.patch('/api/sos/:id/resolve', authRequired, requireRole('citizen'), (req, res) => {
  const alert = db.sosAlerts.find(a => a.id === req.params.id);
  if (!alert) return res.status(404).json({ error: 'Không tìm thấy cảnh báo SOS.' });
  if (alert.userId !== req.user.id) return res.status(403).json({ error: 'Không có quyền với cảnh báo này.' });
  alert.status = 'resolved';
  alert.updatedAt = new Date().toISOString();
  saveDb(db);
  res.json({ alert });
});

// Nhân viên y tế / admin xem danh sách cảnh báo SOS (mới nhất trước)
app.get('/api/sos', authRequired, requireRole('medical', 'admin'), (req, res) => {
  const alerts = [...db.sosAlerts].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 50);
  res.json({ alerts });
});

// Nhân viên y tế xác nhận đã gọi điện / đã cử xe cấp cứu / đóng ca
app.patch('/api/sos/:id/status', authRequired, requireRole('medical', 'admin'), (req, res) => {
  const alert = db.sosAlerts.find(a => a.id === req.params.id);
  if (!alert) return res.status(404).json({ error: 'Không tìm thấy cảnh báo SOS.' });
  const { status } = req.body || {};
  if (!['confirmed', 'resolved'].includes(status)) return res.status(400).json({ error: 'Trạng thái không hợp lệ.' });
  alert.status = status;
  alert.confirmedBy = req.user.name;
  alert.updatedAt = new Date().toISOString();
  saveDb(db);
  res.json({ alert });
});

// ---------------------------------------------------------------------------
// YÊU CẦU / PHẢN ÁNH của người dân → nhân viên y tế tiếp nhận
// ---------------------------------------------------------------------------
app.post('/api/requests', authRequired, requireRole('citizen'), (req, res) => {
  const { type, note } = req.body || {};
  if (!type) return res.status(400).json({ error: 'Thiếu loại yêu cầu.' });

  const request = {
    id: crypto.randomUUID(),
    citizenId: req.user.id,
    citizenName: req.user.name,
    type,
    note: note || '',
    status: 'moi', // moi -> dang_xu_ly -> da_xu_ly
    response: '',
    createdAt: new Date().toISOString(),
  };
  db.requests.push(request);
  saveDb(db);
  res.status(201).json({ request });
});

app.get('/api/requests/mine', authRequired, requireRole('citizen'), (req, res) => {
  const mine = db.requests.filter(r => r.citizenId === req.user.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  res.json({ requests: mine });
});

app.get('/api/requests', authRequired, requireRole('medical', 'admin'), (req, res) => {
  const all = [...db.requests].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  res.json({ requests: all });
});

app.patch('/api/requests/:id', authRequired, requireRole('medical', 'admin'), (req, res) => {
  const request = db.requests.find(r => r.id === req.params.id);
  if (!request) return res.status(404).json({ error: 'Không tìm thấy yêu cầu.' });

  const { status, response } = req.body || {};
  if (status && ['moi', 'dang_xu_ly', 'da_xu_ly'].includes(status)) request.status = status;
  if (typeof response === 'string') request.response = response;
  saveDb(db);
  res.json({ request });
});

// ---------------------------------------------------------------------------
// ĐỀ NGHỊ CUNG CẤP VẬT TƯ (nhân viên y tế tạo, admin theo dõi)
// ---------------------------------------------------------------------------
app.post('/api/supply-proposals', authRequired, requireRole('medical'), (req, res) => {
  const { item, quantity, reason } = req.body || {};
  if (!item) return res.status(400).json({ error: 'Thiếu tên vật tư/thuốc.' });

  const proposal = {
    id: crypto.randomUUID(),
    staffId: req.user.id,
    staffName: req.user.name,
    item,
    quantity: quantity || '',
    reason: reason || '',
    status: 'cho_duyet', // cho_duyet -> da_duyet -> tu_choi
    createdAt: new Date().toISOString(),
  };
  db.supplyProposals.push(proposal);
  saveDb(db);
  res.status(201).json({ proposal });
});

app.get('/api/supply-proposals', authRequired, requireRole('medical', 'admin'), (req, res) => {
  const all = [...db.supplyProposals].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  res.json({ proposals: all });
});

app.patch('/api/supply-proposals/:id', authRequired, requireRole('admin'), (req, res) => {
  const proposal = db.supplyProposals.find(p => p.id === req.params.id);
  if (!proposal) return res.status(404).json({ error: 'Không tìm thấy đề nghị.' });
  const { status } = req.body || {};
  if (status && ['cho_duyet', 'da_duyet', 'tu_choi'].includes(status)) proposal.status = status;
  saveDb(db);
  res.json({ proposal });
});

// ---------------------------------------------------------------------------
// CHATBOT AI (Gemini) — chỉ người dân đã đăng nhập mới được dùng
// ---------------------------------------------------------------------------
app.post('/api/chat', authRequired, requireRole('citizen', 'admin'), async (req, res) => {
  if (!GEMINI_API_KEY) {
    return res.status(500).json({ error: 'Server chưa cấu hình GEMINI_API_KEY.' });
  }
  const { system, messages } = req.body || {};
  if (!Array.isArray(messages)) {
    return res.status(400).json({ error: 'Thiếu trường "messages".' });
  }

  const contents = messages.map(m => ({
    role: m.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: m.content }],
  }));

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': GEMINI_API_KEY },
        body: JSON.stringify({
          contents,
          systemInstruction: system ? { parts: [{ text: system }] } : undefined,
        }),
      }
    );
    const data = await response.json();
    if (!response.ok) {
      console.error('Gemini API error:', data);
      return res.status(response.status).json({ error: data.error?.message || 'Lỗi từ Gemini API' });
    }
    const replyText = data.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('') || '';
    res.json({ content: [{ type: 'text', text: replyText }] });
  } catch (err) {
    console.error('Proxy error:', err);
    res.status(500).json({ error: 'Không thể kết nối đến Gemini API.' });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server Hải Đăng Sức Khỏe đang chạy tại cổng ${PORT}`));
