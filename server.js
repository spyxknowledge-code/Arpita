const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.static(__dirname));
app.use(express.json({ limit: '10mb' }));

const db = new sqlite3.Database('./chat.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    salt TEXT,
    public_key TEXT,
    is_online INTEGER DEFAULT 0,
    last_seen INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
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
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER,
    expires_at INTEGER
  )`);

  // Seed default users
  const defaultUsers = [
    { username: 'Arpita_katli', password: 'arpita123' },
    { username: 'Harsh_kaju', password: 'harsh456' }
  ];
  defaultUsers.forEach(({ username, password }) => {
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
      if (!row) {
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(password + salt, 10);
        db.run('INSERT INTO users (username, password_hash, salt, public_key) VALUES (?, ?, ?, ?)',
          [username, hash, salt, '']);
        console.log(`✅ Seeded default user: ${username}`);
      }
    });
  });
});

// Helper: get user ID from token
const getUserIdFromToken = (token) => {
  return new Promise((resolve, reject) => {
    if (!token) return resolve(null);
    db.get('SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?', [token, Date.now()], (err, row) => {
      if (err) { console.error('DB error in getUserIdFromToken:', err); return resolve(null); }
      resolve(row ? row.user_id : null);
    });
  });
};

// ---------- ROUTES ----------

// SIGN-UP
app.post('/api/signup', (req, res) => {
  const { username, password, publicKey } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (!publicKey) return res.status(400).json({ error: 'Public key required' });
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (row) return res.status(409).json({ error: 'Username already exists' });
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password + salt, 10);
    db.run('INSERT INTO users (username, password_hash, salt, public_key) VALUES (?, ?, ?, ?)',
      [username, hash, salt, publicKey],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to create account' });
        const userId = this.lastID;
        const token = uuidv4();
        db.run('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)',
          [token, userId, Date.now() + 7*24*60*60*1000],
          (err) => {
            if (err) return res.status(500).json({ error: 'Session creation failed' });
            db.run('UPDATE users SET is_online = 1, last_seen = ? WHERE id = ?', [Date.now(), userId]);
            res.json({ token, username, userId, publicKey });
          }
        );
      }
    );
  });
});

// LOGIN
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  db.get('SELECT id, username, password_hash, salt, public_key FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    const isValid = bcrypt.compareSync(password + user.salt, user.password_hash);
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = uuidv4();
    db.run('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)',
      [token, user.id, Date.now() + 7*24*60*60*1000],
      (err) => {
        if (err) return res.status(500).json({ error: 'Session creation failed' });
        db.run('UPDATE users SET is_online = 1, last_seen = ? WHERE id = ?', [Date.now(), user.id]);
        res.json({ token, username: user.username, userId: user.id, publicKey: user.public_key });
      }
    );
  });
});

// LOGOUT
app.post('/api/logout', async (req, res) => {
  const { token } = req.body;
  if (token) {
    const userId = await getUserIdFromToken(token);
    db.run('DELETE FROM sessions WHERE token = ?', [token]);
    if (userId) db.run('UPDATE users SET is_online = 0, last_seen = ? WHERE id = ?', [Date.now(), userId]);
  }
  res.json({ success: true });
});

// UPDATE PUBLIC KEY
app.post('/api/update-public-key', async (req, res) => {
  const { token, publicKey } = req.body;
  const userId = await getUserIdFromToken(token);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  db.run('UPDATE users SET public_key = ? WHERE id = ?', [publicKey, userId]);
  res.json({ success: true });
});

// GET ALL USERS (except self)
app.get('/api/users', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const myId = await getUserIdFromToken(token);
  if (!myId) return res.status(401).json({ error: 'Unauthorized' });
  db.all('SELECT id, username, public_key, is_online FROM users WHERE id != ?', [myId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// GET MESSAGES BETWEEN TWO USERS (sorted)
app.get('/api/messages/:otherId', async (req, res) => {
  const otherId = parseInt(req.params.otherId);
  const token = req.headers.authorization?.split(' ')[1];
  const myId = await getUserIdFromToken(token);
  if (!myId) return res.status(401).json({ error: 'Unauthorized' });
  db.all(
    `SELECT m.*, u1.username as sender_name, u2.username as receiver_name
     FROM messages m
     JOIN users u1 ON m.sender_id = u1.id
     JOIN users u2 ON m.receiver_id = u2.id
     WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
     ORDER BY m.sent_at ASC`,
    [myId, otherId, otherId, myId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// SEARCH MESSAGES (global)
app.post('/api/search', async (req, res) => {
  const { token, query } = req.body;
  const myId = await getUserIdFromToken(token);
  if (!myId) return res.status(401).json({ error: 'Unauthorized' });
  db.all(
    `SELECT * FROM messages WHERE (sender_id = ? OR receiver_id = ?) AND encrypted_content LIKE ? AND is_deleted = 0`,
    [myId, myId, `%${query}%`],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ---------- SOCKET.IO ----------
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
  if (!userId) return socket.disconnect();
  socket.join(`user_${userId}`);

  // Broadcast online to all
  socket.broadcast.emit('user_online', { userId });

  // Typing
  socket.on('typing', ({ receiverId, isTyping }) => {
    socket.to(`user_${receiverId}`).emit('typing', { userId, isTyping });
  });

  // Private message
  socket.on('private_message', ({ receiverId, encryptedContent, iv, salt, replyToId }) => {
    const sentAt = Date.now();
    db.run(
      `INSERT INTO messages (sender_id, receiver_id, encrypted_content, iv, salt, reply_to_id, sent_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [userId, receiverId, encryptedContent, iv, salt, replyToId || null, sentAt],
      function(err) {
        if (err) return socket.emit('message_error', 'Failed to save');
        const msgId = this.lastID;
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
      }
    );
  });

  // Delivered receipt
  socket.on('mark_delivered', ({ messageId }) => {
    db.run('UPDATE messages SET delivered_at = ? WHERE id = ?', [Date.now(), messageId]);
    db.get('SELECT sender_id FROM messages WHERE id = ?', [messageId], (err, row) => {
      if (row) io.to(`user_${row.sender_id}`).emit('delivered_receipt', { messageId });
    });
  });

  // Read receipt
  socket.on('mark_read', ({ messageId }) => {
    db.run('UPDATE messages SET read_at = ? WHERE id = ?', [Date.now(), messageId]);
    db.get('SELECT sender_id FROM messages WHERE id = ?', [messageId], (err, row) => {
      if (row) io.to(`user_${row.sender_id}`).emit('read_receipt', { messageId });
    });
  });

  // Delete message
  socket.on('delete_message', ({ messageId }) => {
    db.run('UPDATE messages SET is_deleted = 1 WHERE id = ? AND (sender_id = ? OR receiver_id = ?)',
      [messageId, userId, userId]);
    db.get('SELECT sender_id, receiver_id FROM messages WHERE id = ?', [messageId], (err, row) => {
      if (row) {
        const otherId = row.sender_id === userId ? row.receiver_id : row.sender_id;
        io.to(`user_${otherId}`).emit('message_deleted', { messageId });
      }
    });
  });

  // Reaction
  socket.on('add_reaction', ({ messageId, reaction }) => {
    db.run('UPDATE messages SET reaction = ? WHERE id = ?', [reaction, messageId]);
    db.get('SELECT sender_id, receiver_id FROM messages WHERE id = ?', [messageId], (err, row) => {
      if (row) {
        const otherId = row.sender_id === userId ? row.receiver_id : row.sender_id;
        io.to(`user_${otherId}`).emit('reaction_added', { messageId, reaction });
      }
    });
  });

  // Disconnect
  socket.on('disconnect', () => {
    db.run('UPDATE users SET is_online = 0, last_seen = ? WHERE id = ?', [Date.now(), userId]);
    socket.broadcast.emit('user_offline', { userId });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server running on port ${PORT}`));
