const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.static(__dirname));
app.use(express.json({ limit: '10mb' }));

const db = new sqlite3.Database('./chat.db');

// ---------- DB setup ----------
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    salt TEXT,
    is_online INTEGER DEFAULT 0,
    last_seen INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER,
    expires_at INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT UNIQUE,
    name TEXT,
    password_hash TEXT,
    salt TEXT,
    created_by INTEGER,
    created_at INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS room_members (
    user_id INTEGER,
    room_id INTEGER,
    joined_at INTEGER,
    PRIMARY KEY (user_id, room_id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id INTEGER,
    sender_id INTEGER,
    encrypted_content TEXT,
    iv TEXT,
    salt TEXT,
    reply_to_id INTEGER,
    reaction TEXT,
    is_deleted INTEGER DEFAULT 0,
    sent_at INTEGER,
    delivered_at INTEGER,
    read_at INTEGER
  )`);

  // Seed default users (Arpita_katli, Harsh_kaju)
  const defaultUsers = [
    { username: 'Arpita_katli', password: 'arpita123' },
    { username: 'Harsh_kaju', password: 'harsh456' }
  ];
  defaultUsers.forEach(({ username, password }) => {
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
      if (!row) {
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(password + salt, 10);
        db.run('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
          [username, hash, salt]);
        console.log(`Seeded user: ${username}`);
      }
    });
  });
});

// ---------- Helpers ----------
const getUserIdFromToken = (token) => {
  return new Promise((resolve, reject) => {
    if (!token) return resolve(null);
    db.get('SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?', [token, Date.now()], (err, row) => {
      if (err || !row) resolve(null);
      else resolve(row.user_id);
    });
  });
};

// ---------- Auth ----------
app.post('/api/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
    if (row) return res.status(409).json({ error: 'Username already exists' });
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password + salt, 10);
    db.run('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
      [username, hash, salt],
      function(err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        const userId = this.lastID;
        const token = uuidv4();
        db.run('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)',
          [token, userId, Date.now() + 7*24*60*60*1000],
          (err) => {
            if (err) return res.status(500).json({ error: 'Session error' });
            db.run('UPDATE users SET is_online = 1, last_seen = ? WHERE id = ?', [Date.now(), userId]);
            res.json({ token, username, userId });
          }
        );
      }
    );
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  db.get('SELECT id, username, password_hash, salt FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!bcrypt.compareSync(password + user.salt, user.password_hash))
      return res.status(401).json({ error: 'Invalid credentials' });
    const token = uuidv4();
    db.run('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)',
      [token, user.id, Date.now() + 7*24*60*60*1000],
      (err) => {
        if (err) return res.status(500).json({ error: 'Session error' });
        db.run('UPDATE users SET is_online = 1, last_seen = ? WHERE id = ?', [Date.now(), user.id]);
        res.json({ token, username: user.username, userId: user.id });
      }
    );
  });
});

app.post('/api/logout', async (req, res) => {
  const { token } = req.body;
  if (token) {
    const userId = await getUserIdFromToken(token);
    db.run('DELETE FROM sessions WHERE token = ?', [token]);
    if (userId) db.run('UPDATE users SET is_online = 0, last_seen = ? WHERE id = ?', [Date.now(), userId]);
  }
  res.json({ success: true });
});

// ---------- Rooms ----------
app.post('/api/create-room', async (req, res) => {
  const { token, roomId, password, roomName } = req.body;
  const userId = await getUserIdFromToken(token);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  if (!roomId || !password) return res.status(400).json({ error: 'Room ID and password required' });
  db.get('SELECT id FROM rooms WHERE room_id = ?', [roomId], (err, row) => {
    if (row) return res.status(409).json({ error: 'Room ID already taken' });
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = bcrypt.hashSync(password + salt, 10);
    db.run('INSERT INTO rooms (room_id, name, password_hash, salt, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [roomId, roomName || roomId, hash, salt, userId, Date.now()],
      function(err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        const roomDbId = this.lastID;
        db.run('INSERT INTO room_members (user_id, room_id, joined_at) VALUES (?, ?, ?)',
          [userId, roomDbId, Date.now()]);
        res.json({ success: true, roomId, salt });
      }
    );
  });
});

app.post('/api/join-room', async (req, res) => {
  const { token, roomId, password } = req.body;
  const userId = await getUserIdFromToken(token);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  if (!roomId || !password) return res.status(400).json({ error: 'Room ID and password required' });
  db.get('SELECT id, password_hash, salt, name FROM rooms WHERE room_id = ?', [roomId], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Room not found' });
    if (!bcrypt.compareSync(password + row.salt, row.password_hash))
      return res.status(401).json({ error: 'Wrong password' });
    db.run('INSERT OR IGNORE INTO room_members (user_id, room_id, joined_at) VALUES (?, ?, ?)',
      [userId, row.id, Date.now()]);
    res.json({ success: true, roomId, salt: row.salt, roomName: row.name });
  });
});

app.get('/api/rooms/:roomId/messages', async (req, res) => {
  const roomId = req.params.roomId;
  const token = req.headers.authorization?.split(' ')[1];
  const userId = await getUserIdFromToken(token);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  db.get('SELECT room_id FROM room_members WHERE user_id = ? AND room_id = (SELECT id FROM rooms WHERE room_id = ?)',
    [userId, roomId], (err, row) => {
      if (!row) return res.status(403).json({ error: 'Not a member' });
      db.all(
        `SELECT m.*, u.username as sender_name
         FROM messages m
         JOIN users u ON m.sender_id = u.id
         WHERE m.room_id = (SELECT id FROM rooms WHERE room_id = ?)
         ORDER BY m.sent_at ASC`,
        [roomId],
        (err, rows) => res.json(rows)
      );
    });
});

app.post('/api/search', async (req, res) => {
  const { token, query } = req.body;
  const userId = await getUserIdFromToken(token);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  db.all(
    `SELECT m.*, u.username as sender_name
     FROM messages m
     JOIN room_members rm ON m.room_id = rm.room_id
     JOIN users u ON m.sender_id = u.id
     WHERE rm.user_id = ? AND m.encrypted_content LIKE ? AND m.is_deleted = 0`,
    [userId, `%${query}%`],
    (err, rows) => res.json(rows)
  );
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ---------- Socket.IO ----------
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  db.get('SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?', [token, Date.now()], (err, row) => {
    if (err || !row) return next(new Error('Invalid token'));
    socket.data.userId = row.user_id;
    next();
  });
});

io.on('connection', (socket) => {
  const userId = socket.data.userId;
  if (!userId) {
    console.log('❌ No userId, disconnecting');
    return socket.disconnect();
  }

  // Get username
  db.get('SELECT username FROM users WHERE id = ?', [userId], (err, row) => {
    if (row) socket.data.username = row.username;
    else socket.data.username = 'User';
    console.log(`✅ ${socket.data.username} (${userId}) connected`);
  });

  // ----- JOIN ROOM -----
  socket.on('join-room', ({ roomId }) => {
    console.log(`📥 Join request: ${socket.data.username} -> ${roomId}`);
    db.get('SELECT id FROM rooms WHERE room_id = ?', [roomId], (err, roomRow) => {
      if (err || !roomRow) {
        socket.emit('error', 'Room not found');
        return;
      }
      db.get('SELECT user_id FROM room_members WHERE user_id = ? AND room_id = ?', [userId, roomRow.id], (err, member) => {
        if (err || !member) {
          socket.emit('error', 'Not a member');
          return;
        }
        // Join socket room
        socket.join(roomId);
        socket.data.currentRoom = roomId;
        console.log(`✅ ${socket.data.username} joined room: ${roomId}`);

        socket.emit('room-joined', { roomId, success: true });

        // Notify others
        socket.to(roomId).emit('user-joined', { username: socket.data.username });

        // Update count
        const roomSockets = io.sockets.adapter.rooms.get(roomId);
        const count = roomSockets ? roomSockets.size : 0;
        io.to(roomId).emit('room-users', { count });
      });
    });
  });

  // ----- TYPING -----
  socket.on('typing', ({ roomId, isTyping }) => {
    socket.to(roomId).emit('typing', { userId, isTyping, username: socket.data.username });
  });

  // ----- MESSAGE (CRITICAL) -----
  socket.on('room-message', async ({ roomId, encryptedContent, iv, salt, replyToId }) => {
    console.log(`📨 Message from ${socket.data.username} in room ${roomId}`);
    const sentAt = Date.now();
    db.get('SELECT id FROM rooms WHERE room_id = ?', [roomId], (err, roomRow) => {
      if (err || !roomRow) {
        socket.emit('error', 'Room not found');
        return;
      }
      db.run(
        `INSERT INTO messages (room_id, sender_id, encrypted_content, iv, salt, reply_to_id, sent_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [roomRow.id, userId, encryptedContent, iv, salt, replyToId || null, sentAt],
        function(err) {
          if (err) {
            console.error('❌ DB insert error:', err);
            socket.emit('message_error', 'Failed to save');
            return;
          }
          const msgId = this.lastID;
          // Broadcast to ALL in room (including sender)
          io.to(roomId).emit('new-message', {
            id: msgId,
            senderId: userId,
            senderName: socket.data.username,
            encryptedContent,
            iv,
            salt,
            replyToId,
            sentAt,
            delivered: false,
            read: false
          });
          console.log(`📤 Message ${msgId} broadcast to room ${roomId}`);
        }
      );
    });
  });

  // ----- RECEIPTS, DELETE, REACTION -----
  socket.on('mark-delivered', ({ messageId, roomId }) => {
    db.run('UPDATE messages SET delivered_at = ? WHERE id = ?', [Date.now(), messageId]);
    socket.to(roomId).emit('delivered-receipt', { messageId });
  });
  socket.on('mark-read', ({ messageId, roomId }) => {
    db.run('UPDATE messages SET read_at = ? WHERE id = ?', [Date.now(), messageId]);
    socket.to(roomId).emit('read-receipt', { messageId });
  });
  socket.on('delete-message', ({ messageId, roomId }) => {
    db.run('UPDATE messages SET is_deleted = 1 WHERE id = ? AND sender_id = ?', [messageId, userId]);
    socket.to(roomId).emit('message-deleted', { messageId });
  });
  socket.on('add-reaction', ({ messageId, reaction, roomId }) => {
    db.run('UPDATE messages SET reaction = ? WHERE id = ?', [reaction, messageId]);
    socket.to(roomId).emit('reaction-added', { messageId, reaction });
  });

  // ----- DISCONNECT -----
  socket.on('disconnect', () => {
    console.log(`❌ ${socket.data.username} disconnected`);
    db.run('UPDATE users SET is_online = 0, last_seen = ? WHERE id = ?', [Date.now(), userId]);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server running on port ${PORT}`));
