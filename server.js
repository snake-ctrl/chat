const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'chat_secret_change_me';

/* ========== 数据库 ========== */
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'chat.db');
const db = new Database(DB_PATH);

const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    lang TEXT DEFAULT 'zh',
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    nickname TEXT NOT NULL,
    text TEXT NOT NULL,
    type TEXT DEFAULT 'normal',
    room TEXT DEFAULT 'public',
    to_user TEXT,
    image TEXT,
    read INTEGER DEFAULT 0,
    revoked INTEGER DEFAULT 0,
    time TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
`);

const insertUser = db.prepare(
  'INSERT INTO users (username, password, lang, created_at) VALUES (?, ?, ?, ?)'
);
const findUser = db.prepare('SELECT * FROM users WHERE username = ?');
const insertMsg = db.prepare(
  `INSERT INTO messages (user_id, nickname, text, type, room, to_user, image, read, revoked, time, created_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
);
const getPublic = db.prepare(
  `SELECT id, nickname, text, type, image, revoked, time FROM messages
   WHERE room = 'public' AND revoked = 0 ORDER BY id DESC LIMIT 100`
);
const getPrivate = db.prepare(
  `SELECT id, nickname, text, type, image, revoked, read, time FROM messages
   WHERE room = 'private' AND revoked = 0
   AND ((nickname = ? AND to_user = ?) OR (nickname = ? AND to_user = ?))
   ORDER BY id DESC LIMIT 100`
);
const getMsgById = db.prepare('SELECT * FROM messages WHERE id = ?');
const revokeMsg = db.prepare('UPDATE messages SET revoked = 1 WHERE id = ?');
const markRead = db.prepare(
  `UPDATE messages SET read = 1 WHERE room = 'private' AND to_user = ? AND nickname = ?`
);
const getUnread = db.prepare(
  `SELECT nickname, COUNT(*) as cnt FROM messages
   WHERE room = 'private' AND to_user = ? AND read = 0 AND revoked = 0
   GROUP BY nickname`
);
const getAllUsers = db.prepare('SELECT username FROM users ORDER BY id');

/* ========== 翻译 ========== */
function translate(text, from, to) {
  return new Promise((resolve) => {
    if (!text) return resolve('');
    if (from === to) return resolve(text);
    const url = `https://translate.googleapis.com/translate_a/single?client=gtx&sl=${from}&tl=${to}&dt=t&q=${encodeURIComponent(text)}`;
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json[0].map(item => item[0]).join(''));
        } catch {
          resolve(text);
        }
      });
    }).on('error', () => resolve(text));
  });
}

function detectLang(text) {
  return /[\u4e00-\u9fa5]/.test(text) ? 'zh' : 'vi';
}

/* ========== 注册 / 登录 ========== */
app.post('/api/register', (req, res) => {
  const { username, password, lang } = req.body;
  if (!username || !password) return res.json({ ok: false, msg: '用户名和密码不能为空' });
  if (username.length < 2 || username.length > 12) return res.json({ ok: false, msg: '用户名 2-12 个字符' });
  if (password.length < 3) return res.json({ ok: false, msg: '密码至少 3 位' });
  if (findUser.get(username)) return res.json({ ok: false, msg: '用户名已存在' });

  const hash = bcrypt.hashSync(password, 10);
  const userLang = lang || 'zh';
  const r = insertUser.run(username, hash, userLang, Date.now());
  const token = jwt.sign({ id: r.lastInsertRowid, username, lang: userLang }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok: true, token, username, lang: userLang });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ ok: false, msg: '用户名和密码不能为空' });
  const user = findUser.get(username);
  if (!user) return res.json({ ok: false, msg: '用户不存在' });
  if (!bcrypt.compareSync(password, user.password)) return res.json({ ok: false, msg: '密码错误' });

  const token = jwt.sign({ id: user.id, username: user.username, lang: user.lang || 'zh' }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok: true, token, username: user.username, lang: user.lang || 'zh' });
});

app.get('/api/users', (req, res) => {
  const list = getAllUsers.all().map(u => u.username);
  res.json({ ok: true, users: list });
});

/* ========== 图片上传 ========== */
app.post('/api/upload', (req, res) => {
  const { image } = req.body;
  if (!image) return res.json({ ok: false, msg: '没有图片' });

  const matches = image.match(/^data:image\/(\w+);base64,(.+)$/);
  if (!matches) return res.json({ ok: false, msg: '图片格式错误' });

  const ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
  const data = Buffer.from(matches[2], 'base64');
  const filename = Date.now() + '_' + Math.random().toString(36).slice(2, 8) + '.' + ext;
  fs.writeFileSync(path.join(UPLOAD_DIR, filename), data);

  res.json({ ok: true, url: '/uploads/' + filename });
});

/* ========== Socket 鉴权 ========== */
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('未登录'));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error('登录已过期'));
  }
});

/* ========== 在线用户 ========== */
const users = {};
const nickToSocket = {};

io.on('connection', (socket) => {
  const nickname = socket.user.username;
  const myLang = socket.user.lang || 'zh';
  users[socket.id] = nickname;
  nickToSocket[nickname] = socket.id;

  // 发公共历史（翻译成自己的语言）
  const history = getPublic.all().reverse();
  (async () => {
    const list = [];
    for (const m of history) {
      const srcLang = detectLang(m.text || '');
      const translated = m.text ? await translate(m.text, srcLang, myLang) : '';
      list.push({ ...m, text: translated });
    }
    socket.emit('history', { room: 'public', list });
  })();

  const unread = getUnread.all(nickname);
  socket.emit('unread', unread);

  const sysText = `${nickname} 加入了聊天室`;
  insertMsg.run(null, '系统', sysText, 'system', 'public', null, null, 0, 0, now(), Date.now());
  io.emit('system', sysText);
  io.emit('userlist', Object.values(users));

  // 公共消息
  socket.on('message', async (payload) => {
    const time = now();
    const text = typeof payload === 'string' ? payload : payload.text;
    const image = typeof payload === 'string' ? null : payload.image;

    const srcLang = detectLang(text || '');
    const r = insertMsg.run(socket.user.id, nickname, text || '', 'normal', 'public', null, image || null, 0, 0, time, Date.now());
    const msgId = r.lastInsertRowid;

    for (const [sid, uname] of Object.entries(users)) {
      const targetSocket = io.sockets.sockets.get(sid);
      if (!targetSocket) continue;
      const targetLang = targetSocket.user.lang || 'zh';
      const translated = text ? await translate(text, srcLang, targetLang) : '';
      targetSocket.emit('message', {
        id: msgId,
        nickname,
        text: translated,
        image,
        time,
        room: 'public',
      });
    }
  });

  // 私聊
  socket.on('private', async ({ to, text, image }) => {
    const time = now();
    const targetSocket = nickToSocket[to];
    if (!targetSocket) {
      socket.emit('private_error', { to, msg: '对方不在线' });
      return;
    }

    const srcLang = detectLang(text || '');
    const targetSock = io.sockets.sockets.get(targetSocket);
    const targetLang = targetSock ? (targetSock.user.lang || 'zh') : 'zh';
    const translated = text ? await translate(text, srcLang, targetLang) : '';

    const r = insertMsg.run(socket.user.id, nickname, text || '', 'normal', 'private', to, image || null, 0, 0, time, Date.now());

    // 发给对方：翻译后
    io.to(targetSocket).emit('private', {
      id: r.lastInsertRowid,
      from: nickname,
      to,
      text: translated,
      image,
      time,
    });

    // 发给自己：原文
    socket.emit('private', {
      id: r.lastInsertRowid,
      from: nickname,
      to,
      text: text || '',
      image,
      time,
      self: true,
    });
  });

  // 私聊历史
  socket.on('private_history', async (other) => {
    const list = getPrivate.all(nickname, other, other, nickname).reverse();
    const result = [];
    for (const m of list) {
      const srcLang = detectLang(m.text || '');
      const translated = m.text ? await translate(m.text, srcLang, myLang) : '';
      result.push({ ...m, text: translated });
    }
    socket.emit('private_history', { other, list: result });
    markRead.run(nickname, other);
    socket.emit('unread', getUnread.all(nickname));
  });

  // 撤回
  socket.on('revoke', ({ id, to }) => {
    const msg = getMsgById.get(id);
    if (!msg) return;
    if (msg.nickname !== nickname) return;

    revokeMsg.run(id);
    if (msg.room === 'public') {
      io.emit('revoked', { id, room: 'public' });
    } else {
      const targetSocket = nickToSocket[to];
      if (targetSocket) io.to(targetSocket).emit('revoked', { id, room: 'private', from: nickname });
      socket.emit('revoked', { id, room: 'private' });
    }
  });

  socket.on('disconnect', () => {
    delete users[socket.id];
    delete nickToSocket[nickname];
    const sysText = `${nickname} 离开了聊天室`;
    insertMsg.run(null, '系统', sysText, 'system', 'public', null, null, 0, 0, now(), Date.now());
    io.emit('system', sysText);
    io.emit('userlist', Object.values(users));
  });
});

function now() {
  return new Date().toLocaleTimeString('zh-CN', { hour12: false });
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log('聊天室已启动，端口：' + PORT);
});
