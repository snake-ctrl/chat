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
    nickname TEXT,
    avatar TEXT,
    lang TEXT DEFAULT 'zh',
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS friends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    friend_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(user_id, friend_id)
  );

  CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT DEFAULT 'private',
    name TEXT,
    avatar TEXT,
    owner_id INTEGER,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS chat_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT DEFAULT 'member',
    joined_at INTEGER NOT NULL,
    UNIQUE(chat_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    user_id INTEGER,
    nickname TEXT NOT NULL,
    text TEXT NOT NULL,
    type TEXT DEFAULT 'normal',
    image TEXT,
    status TEXT DEFAULT 'sent',
    revoked INTEGER DEFAULT 0,
    time TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
`);

const insertUser = db.prepare(
  'INSERT INTO users (username, password, nickname, avatar, lang, created_at) VALUES (?, ?, ?, ?, ?, ?)'
);
const findUser = db.prepare('SELECT * FROM users WHERE username = ?');
const findUserById = db.prepare('SELECT * FROM users WHERE id = ?');
const updateUser = db.prepare('UPDATE users SET nickname = ?, avatar = ? WHERE id = ?');
const searchUsers = db.prepare(
  "SELECT id, username, nickname, avatar FROM users WHERE username LIKE ? OR nickname LIKE ? LIMIT 20"
);
const insertFriend = db.prepare(
  'INSERT OR IGNORE INTO friends (user_id, friend_id, created_at) VALUES (?, ?, ?)'
);
const getFriends = db.prepare(
  `SELECT u.id, u.username, u.nickname, u.avatar FROM friends f
   JOIN users u ON f.friend_id = u.id
   WHERE f.user_id = ?`
);
const isFriend = db.prepare('SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ?');

const insertChat = db.prepare(
  'INSERT INTO chats (type, name, avatar, owner_id, created_at) VALUES (?, ?, ?, ?, ?)'
);
const getChatById = db.prepare('SELECT * FROM chats WHERE id = ?');
const insertMember = db.prepare(
  'INSERT OR IGNORE INTO chat_members (chat_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)'
);
const getChatMembers = db.prepare(
  `SELECT u.id, u.username, u.nickname, u.avatar, cm.role FROM chat_members cm
   JOIN users u ON cm.user_id = u.id
   WHERE cm.chat_id = ?`
);
const getUserChats = db.prepare(
  `SELECT c.* FROM chats c
   JOIN chat_members cm ON c.id = cm.chat_id
   WHERE cm.user_id = ?
   ORDER BY c.created_at DESC`
);
const findPrivateChat = db.prepare(
  `SELECT c.id FROM chats c
   JOIN chat_members m1 ON c.id = m1.chat_id AND m1.user_id = ?
   JOIN chat_members m2 ON c.id = m2.chat_id AND m2.user_id = ?
   WHERE c.type = 'private'
   LIMIT 1`
);
const updateChatInfo = db.prepare('UPDATE chats SET name = ?, avatar = ? WHERE id = ?');

const insertMsg = db.prepare(
  `INSERT INTO messages (chat_id, user_id, nickname, text, type, image, status, revoked, time, created_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
);
const getChatMessages = db.prepare(
  `SELECT id, user_id, nickname, text, type, image, status, revoked, time, created_at
   FROM messages WHERE chat_id = ? AND revoked = 0 ORDER BY id DESC LIMIT 100`
);
const getMsgById = db.prepare('SELECT * FROM messages WHERE id = ?');
const revokeMsg = db.prepare('UPDATE messages SET revoked = 1 WHERE id = ?');
const markRead = db.prepare(
  `UPDATE messages SET status = 'read' WHERE chat_id = ? AND user_id != ? AND status = 'sent'`
);

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
  const r = insertUser.run(username, hash, username, null, userLang, Date.now());
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

/* ========== 用户资料 ========== */
app.get('/api/me', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.json({ ok: false });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = findUserById.get(payload.id);
    if (!user) return res.json({ ok: false });
    res.json({ ok: true, user: { id: user.id, username: user.username, nickname: user.nickname || user.username, avatar: user.avatar, lang: user.lang } });
  } catch {
    res.json({ ok: false });
  }
});

app.put('/api/me', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.json({ ok: false });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { nickname, avatar } = req.body;
    updateUser.run(nickname || payload.username, avatar || null, payload.id);
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

app.get('/api/search', (req, res) => {
  const q = req.query.q || '';
  if (!q) return res.json({ ok: true, users: [] });
  const list = searchUsers.all(`%${q}%`, `%${q}%`);
  res.json({ ok: true, users: list });
});

/* ========== 好友 ========== */
app.get('/api/friends', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.json({ ok: false });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const list = getFriends.all(payload.id);
    res.json({ ok: true, friends: list });
  } catch {
    res.json({ ok: false });
  }
});

app.post('/api/friends', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.json({ ok: false });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { friendId } = req.body;
    insertFriend.run(payload.id, friendId, Date.now());
    insertFriend.run(friendId, payload.id, Date.now());
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

app.delete('/api/friends/:id', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.json({ ok: false });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    db.prepare('DELETE FROM friends WHERE user_id = ? AND friend_id = ?').run(payload.id, req.params.id);
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
});

/* ========== 会话 ========== */
app.get('/api/chats', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.json({ ok: false });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const chats = getUserChats.all(payload.id);
    const result = chats.map(c => {
      const members = getChatMembers.all(c.id);
      return { ...c, members };
    });
    res.json({ ok: true, chats: result });
  } catch {
    res.json({ ok: false });
  }
});

// 创建私聊
app.post('/api/chats/private', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.json({ ok: false });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { userId } = req.body;
    if (userId === payload.id) return res.json({ ok: false, msg: '不能和自己聊天' });

    let existing = findPrivateChat.get(payload.id, userId);
    if (existing) return res.json({ ok: true, chatId: existing.id });

    const r = insertChat.run('private', null, null, payload.id, Date.now());
    const chatId = r.lastInsertRowid;
    insertMember.run(chatId, payload.id, 'member', Date.now());
    insertMember.run(chatId, userId, 'member', Date.now());

    res.json({ ok: true, chatId });
  } catch {
    res.json({ ok: false });
  }
});

// 创建群组/频道
app.post('/api/chats/group', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.json({ ok: false });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { name, avatar, type, memberIds } = req.body;
    if (!name) return res.json({ ok: false, msg: '名称不能为空' });

    const r = insertChat.run(type || 'group', name, avatar || null, payload.id, Date.now());
    const chatId = r.lastInsertRowid;
    insertMember.run(chatId, payload.id, 'owner', Date.now());
    (memberIds || []).forEach(id => insertMember.run(chatId, id, 'member', Date.now()));

    res.json({ ok: true, chatId });
  } catch {
    res.json({ ok: false });
  }
});

// 更新群组信息
app.put('/api/chats/:id', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.json({ ok: false });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { name, avatar } = req.body;
    updateChatInfo.run(name, avatar || null, req.params.id);
    res.json({ ok: true });
  } catch {
    res.json({ ok: false });
  }
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
const onlineUsers = {}; // socket.id -> { id, username, nickname, avatar, lang }
const userSockets = {}; // user.id -> socket.id

io.on('connection', (socket) => {
  const u = socket.user;
  const dbUser = findUserById.get(u.id);
  if (!dbUser) return socket.disconnect();

  const me = {
    id: dbUser.id,
    username: dbUser.username,
    nickname: dbUser.nickname || dbUser.username,
    avatar: dbUser.avatar,
    lang: dbUser.lang || 'zh',
  };
  onlineUsers[socket.id] = me;
  userSockets[me.id] = socket.id;

  // 加入自己的所有会话房间
  const myChats = getUserChats.all(me.id);
  myChats.forEach(c => socket.join('chat_' + c.id));

  // 上线通知
  io.emit('online', { userId: me.id, online: true });

  // 加载会话列表
  socket.emit('chats', myChats.map(c => ({ ...c, members: getChatMembers.all(c.id) })));

  // 发消息
  socket.on('send_message', async ({ chatId, text, image }) => {
    const time = now();
    const srcLang = detectLang(text || '');
    const r = insertMsg.run(chatId, me.id, me.nickname, text || '', 'normal', image || null, 'sent', 0, time, Date.now());
    const msgId = r.lastInsertRowid;

    const members = getChatMembers.all(chatId);

    // 给每个成员发翻译后的版本
    for (const m of members) {
      const targetSocketId = userSockets[m.id];
      if (!targetSocketId) continue;
      const targetSocket = io.sockets.sockets.get(targetSocketId);
      if (!targetSocket) continue;

      const targetLang = targetSocket.user.lang || 'zh';
      const translated = text ? await translate(text, srcLang, targetLang) : '';

      targetSocket.emit('new_message', {
        id: msgId,
        chatId,
        userId: me.id,
        nickname: me.nickname,
        avatar: me.avatar,
        text: translated,
        image,
        time,
        status: 'sent',
        self: m.id === me.id,
      });
    }
  });

  // 已读
  socket.on('mark_read', ({ chatId }) => {
    markRead.run(chatId, me.id);
    io.to('chat_' + chatId).emit('read', { chatId, userId: me.id });
  });

  // 撤回
  socket.on('revoke', ({ id, chatId }) => {
    const msg = getMsgById.get(id);
    if (!msg || msg.user_id !== me.id) return;
    revokeMsg.run(id);
    io.to('chat_' + chatId).emit('revoked', { id, chatId });
  });

  // 加入会话房间
  socket.on('join_chat', (chatId) => {
    socket.join('chat_' + chatId);
  });

  // 更新资料
  socket.on('update_profile', ({ nickname, avatar }) => {
    updateUser.run(nickname, avatar, me.id);
    me.nickname = nickname;
    me.avatar = avatar;
    onlineUsers[socket.id] = me;
    io.emit('profile_updated', { userId: me.id, nickname, avatar });
  });

  socket.on('disconnect', () => {
    delete onlineUsers[socket.id];
    delete userSockets[me.id];
    io.emit('online', { userId: me.id, online: false });
  });
});

function now() {
  return new Date().toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit' });
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log('聊天室已启动，端口：' + PORT);
});
