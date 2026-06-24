const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.static(__dirname));
app.use(express.json({ limit: '10mb' }));

// SQLite DB
const db = new Database('./chat.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    salt TEXT,
    public_key TEXT,
    is_online INTEGER DEFAULT 0,
    last_seen INTEGER
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    receiver_id INTEGER,
    encrypted_content TEXT,
    iv TEXT,
    salt TEXT,
    reply_to_id INTEGER,
    reaction TEXT,
    is_deleted INTEGER DEFAULT 0,
    sent_at INTEGER,
    delivered_at INTEGER,
    read_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER,
    expires_at INTEGER
  );
`);

// Seed default users (if not exist)
const seedUsers = () => {
  const users = [
    { username: 'Arpita_katli', password: 'arpita123' },
    { username: 'Harsh_kaju', password: 'harsh456' }
  ];
  const insert = db.prepare('INSERT OR IGNORE INTO users (username, password_hash, salt, public_key) VALUES (?, ?, ?, ?)');
  users.forEach(({ username, password }) => {
    const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (!exists) {
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(password + salt, 10);
      insert.run(username, hash, salt, '');
    }
  });
};
seedUsers();

// Helper: get user ID from token
const getUserIdFromToken = (token) => {
  if (!token) return null;
  const row = db.prepare('SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?').get(token, Date.now());
  return row ? row.user_id : null;
};

// ---------- Routes ----------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  const user = db.prepare('SELECT id, username, password_hash, salt, public_key FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (!bcrypt.compareSync(password + user.salt, user.password_hash))
    return res.status(401).json({ error: 'Invalid credentials' });
  const token = uuidv4();
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .run(token, user.id, Date.now() + 7*24*60*60*1000);
  db.prepare('UPDATE users SET is_online = 1, last_seen = ? WHERE id = ?').run(Date.now(), user.id);
  res.json({ token, username: user.username, userId: user.id, publicKey: user.public_key });
});

app.post('/api/logout', (req, res) => {
  const { token } = req.body;
  if (token) {
    const userId = getUserIdFromToken(token);
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    if (userId) db.prepare('UPDATE users SET is_online = 0, last_seen = ? WHERE id = ?').run(Date.now(), userId);
  }
  res.json({ success: true });
});

app.post('/api/update-public-key', (req, res) => {
  const { token, publicKey } = req.body;
  const userId = getUserIdFromToken(token);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  db.prepare('UPDATE users SET public_key = ? WHERE id = ?').run(publicKey, userId);
  res.json({ success: true });
});

app.get('/api/other-user/:userId', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const myId = getUserIdFromToken(token);
  if (!myId) return res.status(401).json({ error: 'Unauthorized' });
  const otherId = myId === 1 ? 2 : 1;
  const row = db.prepare('SELECT id, username, public_key, is_online FROM users WHERE id = ?').get(otherId);
  if (!row) return res.status(404).json({ error: 'User not found' });
  res.json(row);
});

app.get('/api/messages/:otherId', (req, res) => {
  const otherId = parseInt(req.params.otherId);
  const token = req.headers.authorization?.split(' ')[1];
  const myId = getUserIdFromToken(token);
  if (!myId) return res.status(401).json({ error: 'Unauthorized' });
  const rows = db.prepare(`
    SELECT m.*, u1.username as sender_name, u2.username as receiver_name
    FROM messages m
    JOIN users u1 ON m.sender_id = u1.id
    JOIN users u2 ON m.receiver_id = u2.id
    WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
    ORDER BY m.sent_at ASC
  `).all(myId, otherId, otherId, myId);
  res.json(rows);
});

app.post('/api/search', (req, res) => {
  const { token, query } = req.body;
  const myId = getUserIdFromToken(token);
  if (!myId) return res.status(401).json({ error: 'Unauthorized' });
  const rows = db.prepare(
    `SELECT * FROM messages WHERE (sender_id = ? OR receiver_id = ?) AND encrypted_content LIKE ? AND is_deleted = 0`
  ).all(myId, myId, `%${query}%`);
  res.json(rows);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ---------- Socket.IO ----------
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  const row = db.prepare('SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?').get(token, Date.now());
  if (!row) return next(new Error('Invalid token'));
  socket.data.userId = row.user_id;
  next();
});

io.on('connection', (socket) => {
  const userId = socket.data.userId;
  if (!userId) return socket.disconnect();
  socket.join(`user_${userId}`);
  const otherId = userId === 1 ? 2 : 1;

  socket.broadcast.emit('user_online', { userId });

  socket.on('typing', ({ receiverId, isTyping }) => {
    socket.to(`user_${receiverId}`).emit('typing', { userId, isTyping });
  });

  socket.on('private_message', ({ receiverId, encryptedContent, iv, salt, replyToId }) => {
    const sentAt = Date.now();
    const stmt = db.prepare(
      `INSERT INTO messages (sender_id, receiver_id, encrypted_content, iv, salt, reply_to_id, sent_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    );
    const info = stmt.run(userId, receiverId, encryptedContent, iv, salt, replyToId || null, sentAt);
    const msgId = info.lastInsertRowid;
    io.to(`user_${receiverId}`).emit('new_message', {
      id: msgId,
      senderId: userId,
      receiverId,
      encryptedContent,
      iv,
      salt,
      replyToId,
      sentAt,
      delivered: false,
      read: false
    });
    socket.emit('message_sent', { id: msgId, sentAt });
  });

  socket.on('mark_delivered', ({ messageId }) => {
    db.prepare('UPDATE messages SET delivered_at = ? WHERE id = ?').run(Date.now(), messageId);
    const senderId = userId === 1 ? 2 : 1;
    io.to(`user_${senderId}`).emit('delivered_receipt', { messageId });
  });

  socket.on('mark_read', ({ messageId }) => {
    db.prepare('UPDATE messages SET read_at = ? WHERE id = ?').run(Date.now(), messageId);
    const senderId = userId === 1 ? 2 : 1;
    io.to(`user_${senderId}`).emit('read_receipt', { messageId });
  });

  socket.on('delete_message', ({ messageId }) => {
    db.prepare('UPDATE messages SET is_deleted = 1 WHERE id = ? AND (sender_id = ? OR receiver_id = ?)')
      .run(messageId, userId, userId);
    io.to(`user_${otherId}`).emit('message_deleted', { messageId });
  });

  socket.on('add_reaction', ({ messageId, reaction }) => {
    db.prepare('UPDATE messages SET reaction = ? WHERE id = ?').run(reaction, messageId);
    io.to(`user_${otherId}`).emit('reaction_added', { messageId, reaction });
  });

  socket.on('disconnect', () => {
    db.prepare('UPDATE users SET is_online = 0, last_seen = ? WHERE id = ?').run(Date.now(), userId);
    socket.broadcast.emit('user_offline', { userId });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));
