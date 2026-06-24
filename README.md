# Arpita Chats

End-to-end encrypted private chat for two users (Arpita_katli & Harsh_kaju).  
Built with Node.js, Express, Socket.IO, better-sqlite3, and Web Crypto API.

## Features
- E2EE using ECDH + AES-GCM
- Real-time messaging, typing, online status, read receipts
- Message reactions, delete, reply, search, file & voice sharing
- Dark glassmorphism UI, responsive
- Fake IP block after 10 failed login attempts (client-side)

## Deploy on Render
1. Push this repo to GitHub.
2. Create a Web Service on Render, connect repo.
3. Build: `npm install`, Start: `npm start`.
4. Done.

## Default credentials
- Arpita_katli / arpita123
- Harsh_kaju / harsh456

## Add more users
Run SQLite commands or modify `seedUsers()` in server.js.
