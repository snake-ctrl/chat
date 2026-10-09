const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/* ========== 配置 ========== */
const JWT_SECRET = 'chat_secret_change_me'; // 生产环境请改成随机字符串

/* ========== 数据库 ========== */
const db = new Database(path.join(__dirname, 'chat.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    nickname TEXT NOT NULL,
    text TEXT NOT NULL,
    type TEXT DEFAULT 'normal',
    time TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
`);

const insertUser = db.prepare(
  'INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)'
);
const findUser = db.prepare('SELECT * FROM users WHERE username = ?');
const insertMsg = db.prepare(
  'INSERT INTO messages (user_id, nickname, text, type, time, created_at) VALUES (?, ?, ?, ?, ?, ?)'
);
const getRecent = db.prepare(
  'SELECT nickname, text, type, time FROM messages ORDER BY id DESC LIMIT 100'
);

/* ========== HTTP 接口：注册 / 登录 ========== */
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ ok: false, msg: '用户名和密码不能为空' });
  if (username.length < 2 || username.length > 12) return res.json({ ok: false, msg: '用户名 2-12 个字符' });
  if (password.length < 3) return res.json({ ok: false, msg: '密码至少 3 位' });

  if (findUser.get(username)) return res.json({ ok: false, msg: '用户名已存在' });

  const hash = bcrypt.hashSync(password, 10);
  const r = insertUser.run(username, hash, Date.now());
  const token = jwt.sign({ id: r.lastInsertRowid, username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok: true, token, username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ ok: false, msg: '用户名和密码不能为空' });

  const user = findUser.get(username);
  if (!user) return res.json({ ok: false, msg: '用户不存在' });
  if (!bcrypt.compareSync(password, user.password)) return res.json({ ok: false, msg: '密码错误' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok: true, token, username: user.username });
});

/* ========== Socket.IO 鉴权 ========== */
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('未登录'));
  try {
    const user = jwt.verify(token, JWT_SECRET);
    socket.user = user;
    next();
  } catch {
    next(new Error('登录已过期'));
  }
});

/* ========== 在线用户 ========== */
const users = {};

io.on('connection', (socket) => {
  const nickname = socket.user.username;
  users[socket.id] = nickname;
  console.log('上线:', nickname);

  // 发历史消息
  const history = getRecent.all().reverse();
  socket.emit('history', history);

  // 系统消息
  const sysText = `${nickname} 加入了聊天室`;
  insertMsg.run(null, '系统', sysText, 'system', now(), Date.now());
  io.emit('system', sysText);
  io.emit('userlist', Object.values(users));

  // 收到消息
  socket.on('message', (text) => {
    const time = now();
    insertMsg.run(socket.user.id, nickname, text, 'normal', time, Date.now());
    io.emit('message', { nickname, text, time });
  });

  // 断开
  socket.on('disconnect', () => {
    delete users[socket.id];
    const sysText = `${nickname} 离开了聊天室`;
    insertMsg.run(null, '系统', sysText, 'system', now(), Date.now());
    io.emit('system', sysText);
    io.emit('userlist', Object.values(users));
    console.log('下线:', nickname);
  });
});

function now() {
  return new Date().toLocaleTimeString('zh-CN', { hour12: false });
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log('聊天室已启动，端口：' + PORT);
});