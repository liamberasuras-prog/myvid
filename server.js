// MyVids Pro backend - zero dependencies (Node 16+).
// Run: node server.js   (then open http://localhost:3000)
//
// Everything is stored on disk in ./data (override with DATA_DIR):
//   data/db.json        users (hashed passwords), sessions, video metadata
//   data/videos/<id>    video files
//   data/avatars/<user> profile pictures
// Back up or mount the ./data folder and nothing is ever lost.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const VIDEO_DIR = path.join(DATA_DIR, 'videos');
const AVATAR_DIR = path.join(DATA_DIR, 'avatars');
const PUBLIC_DIR = path.join(__dirname, 'public');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const MAX_VIDEO_BYTES = Number(process.env.MAX_VIDEO_BYTES) || 2 * 1024 * 1024 * 1024; // 2 GB
const MAX_AVATAR_BYTES = 5 * 1024 * 1024; // 5 MB

fs.mkdirSync(VIDEO_DIR, { recursive: true });
fs.mkdirSync(AVATAR_DIR, { recursive: true });

// ---------- tiny JSON "database" ----------
let db = { users: {}, sessions: {}, videos: [] };
if (fs.existsSync(DB_FILE)) {
  try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))); }
  catch (e) { console.error('Could not read db.json:', e); process.exit(1); }
}
function saveDb() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE); // atomic replace
}

// ---------- helpers ----------
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function checkPassword(password, user) {
  const { hash } = hashPassword(password, user.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.hash, 'hex'));
}
function send(res, status, body, headers = {}) {
  const isObj = typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(status, Object.assign({ 'Content-Type': isObj ? 'application/json' : 'text/plain' }, headers));
  res.end(isObj ? JSON.stringify(body) : body);
}
function readJson(req, limit = 100 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(new Error('Body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
function authUser(req) {
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (!m) return null;
  const s = db.sessions[m[1]];
  return s && db.users[s] ? s : null;
}
const validUsername = u => typeof u === 'string' && /^[A-Za-z0-9_-]{3,32}$/.test(u);
const validPassword = p => typeof p === 'string' && p.length >= 6 && p.length <= 200;

function publicVideo(v) {
  const author = db.users[v.author];
  return {
    id: v.id, title: v.title, author: v.author, timestamp: v.timestamp, mime: v.mime,
    authorAvatarV: author && author.avatarV ? author.avatarV : null
  };
}

// Streams a file with HTTP Range support (needed for seeking in <video>)
function serveFile(req, res, file, mime, extra = {}) {
  fs.stat(file, (err, stat) => {
    if (err) return send(res, 404, { error: 'Not found' });
    const size = stat.size;
    const range = req.headers.range;
    const base = Object.assign({ 'Content-Type': mime, 'Accept-Ranges': 'bytes' }, extra);
    if (range) {
      const m = /bytes=(\d*)-(\d*)/.exec(range);
      let start = m && m[1] ? parseInt(m[1], 10) : 0;
      let end = m && m[2] ? parseInt(m[2], 10) : size - 1;
      if (m && !m[1] && m[2]) { start = Math.max(0, size - parseInt(m[2], 10)); end = size - 1; }
      if (isNaN(start) || isNaN(end) || start > end || start >= size) {
        res.writeHead(416, { 'Content-Range': `bytes */${size}` });
        return res.end();
      }
      end = Math.min(end, size - 1);
      res.writeHead(206, Object.assign(base, {
        'Content-Range': `bytes ${start}-${end}/${size}`, 'Content-Length': end - start + 1
      }));
      fs.createReadStream(file, { start, end }).pipe(res);
    } else {
      res.writeHead(200, Object.assign(base, { 'Content-Length': size }));
      fs.createReadStream(file).pipe(res);
    }
  });
}

// Streams an upload straight to disk with a size cap
function receiveUpload(req, res, destFile, maxBytes, onDone) {
  const declared = Number(req.headers['content-length'] || 0);
  if (declared > maxBytes) return send(res, 413, { error: 'File too large' }, { Connection: 'close' });
  const tmp = destFile + '.part';
  const ws = fs.createWriteStream(tmp);
  let size = 0, aborted = false;
  req.on('data', chunk => {
    size += chunk.length;
    if (size > maxBytes && !aborted) {
      aborted = true;
      req.unpipe(ws); ws.destroy();
      fs.unlink(tmp, () => {});
      send(res, 413, { error: 'File too large' }, { Connection: 'close' });
    }
  });
  req.pipe(ws);
  ws.on('finish', () => {
    if (aborted) return;
    if (size === 0) { fs.unlink(tmp, () => {}); return send(res, 400, { error: 'Empty upload' }); }
    fs.rename(tmp, destFile, err => {
      if (err) return send(res, 500, { error: 'Could not save file' });
      onDone();
    });
  });
  const fail = () => { if (!aborted) { aborted = true; ws.destroy(); fs.unlink(tmp, () => {}); } };
  req.on('aborted', fail);
  req.on('error', fail);
  ws.on('error', () => { fail(); if (!res.headersSent) send(res, 500, { error: 'Write failed' }); });
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };

// ---------- routes ----------
async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  const method = req.method;

  try {
    if (p === '/api/register' && method === 'POST') {
      const { username, password } = await readJson(req);
      if (!validUsername(username)) return send(res, 400, { error: 'Username must be 3-32 letters, numbers, _ or -.' });
      if (!validPassword(password)) return send(res, 400, { error: 'Password must be at least 6 characters.' });
      if (Object.keys(db.users).some(u => u.toLowerCase() === username.toLowerCase()))
        return send(res, 409, { error: 'Username already registered.' });
      const { salt, hash } = hashPassword(password);
      db.users[username] = { salt, hash, avatarV: null, avatarMime: null, created: Date.now() };
      const token = crypto.randomBytes(32).toString('hex');
      db.sessions[token] = username;
      saveDb();
      return send(res, 200, { token, username, avatarV: null });
    }

    if (p === '/api/login' && method === 'POST') {
      const { username, password } = await readJson(req);
      const user = db.users[username];
      if (!user || typeof password !== 'string' || !checkPassword(password, user))
        return send(res, 401, { error: 'Invalid username or password.' });
      const token = crypto.randomBytes(32).toString('hex');
      db.sessions[token] = username;
      saveDb();
      return send(res, 200, { token, username, avatarV: user.avatarV });
    }

    if (p === '/api/me' && method === 'GET') {
      const u = authUser(req);
      if (!u) return send(res, 401, { error: 'Not signed in' });
      return send(res, 200, { username: u, avatarV: db.users[u].avatarV });
    }

    if (p === '/api/logout' && method === 'POST') {
      const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
      if (m && db.sessions[m[1]]) { delete db.sessions[m[1]]; saveDb(); }
      return send(res, 200, { ok: true });
    }

    if (p === '/api/password' && method === 'POST') {
      const u = authUser(req);
      if (!u) return send(res, 401, { error: 'Not signed in' });
      const { oldPassword, newPassword } = await readJson(req);
      if (!checkPassword(String(oldPassword || ''), db.users[u])) return send(res, 403, { error: 'Current password is incorrect.' });
      if (!validPassword(newPassword)) return send(res, 400, { error: 'New password must be at least 6 characters.' });
      const { salt, hash } = hashPassword(newPassword);
      db.users[u].salt = salt; db.users[u].hash = hash;
      // sign out every other session for this user
      const current = /^Bearer (.+)$/.exec(req.headers.authorization)[1];
      for (const t of Object.keys(db.sessions)) if (db.sessions[t] === u && t !== current) delete db.sessions[t];
      saveDb();
      return send(res, 200, { ok: true });
    }

    if (p === '/api/avatar' && method === 'POST') {
      const u = authUser(req);
      if (!u) return send(res, 401, { error: 'Not signed in' });
      const mime = (req.headers['content-type'] || '').split(';')[0];
      if (!['image/png', 'image/jpeg', 'image/webp'].includes(mime)) return send(res, 400, { error: 'PNG, JPEG or WebP only.' });
      return receiveUpload(req, res, path.join(AVATAR_DIR, u), MAX_AVATAR_BYTES, () => {
        db.users[u].avatarV = Date.now();
        db.users[u].avatarMime = mime;
        saveDb();
        send(res, 200, { avatarV: db.users[u].avatarV });
      });
    }

    let m;
    if ((m = /^\/api\/avatar\/([A-Za-z0-9_-]{3,32})$/.exec(p)) && method === 'GET') {
      const user = db.users[m[1]];
      if (!user || !user.avatarV) return send(res, 404, { error: 'No avatar' });
      return serveFile(req, res, path.join(AVATAR_DIR, m[1]), user.avatarMime, { 'Cache-Control': 'public, max-age=31536000' });
    }

    if (p === '/api/videos' && method === 'GET') {
      const list = db.videos.slice().sort((a, b) => b.timestamp - a.timestamp).map(publicVideo);
      return send(res, 200, list);
    }

    if (p === '/api/videos' && method === 'POST') {
      const u = authUser(req);
      if (!u) return send(res, 401, { error: 'Not signed in' });
      const title = (url.searchParams.get('title') || '').trim().slice(0, 150);
      const mime = (req.headers['content-type'] || '').split(';')[0];
      if (!title) return send(res, 400, { error: 'Title is required.' });
      if (!mime.startsWith('video/')) return send(res, 400, { error: 'File must be a video.' });
      const id = crypto.randomUUID();
      return receiveUpload(req, res, path.join(VIDEO_DIR, id), MAX_VIDEO_BYTES, () => {
        const video = { id, title, author: u, timestamp: Date.now(), mime };
        db.videos.push(video);
        saveDb();
        send(res, 200, publicVideo(video));
      });
    }

    if ((m = /^\/api\/videos\/([0-9a-f-]{36})$/.exec(p)) && method === 'DELETE') {
      const u = authUser(req);
      if (!u) return send(res, 401, { error: 'Not signed in' });
      const i = db.videos.findIndex(v => v.id === m[1]);
      if (i < 0) return send(res, 404, { error: 'Not found' });
      if (db.videos[i].author !== u) return send(res, 403, { error: 'Not your video' });
      db.videos.splice(i, 1);
      saveDb();
      fs.unlink(path.join(VIDEO_DIR, m[1]), () => {});
      return send(res, 200, { ok: true });
    }

    if ((m = /^\/media\/([0-9a-f-]{36})$/.exec(p)) && method === 'GET') {
      const v = db.videos.find(x => x.id === m[1]);
      if (!v) return send(res, 404, { error: 'Not found' });
      return serveFile(req, res, path.join(VIDEO_DIR, v.id), v.mime, { 'Cache-Control': 'public, max-age=86400' });
    }

    // static front-end
    if (method === 'GET' && !p.startsWith('/api/')) {
      const rel = p === '/' ? 'index.html' : p.slice(1);
      const file = path.normalize(path.join(PUBLIC_DIR, rel));
      if (!file.startsWith(PUBLIC_DIR)) return send(res, 403, 'Forbidden');
      if (fs.existsSync(file) && fs.statSync(file).isFile())
        return serveFile(req, res, file, MIME[path.extname(file)] || 'application/octet-stream');
    }

    send(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error(e);
    if (!res.headersSent) send(res, 400, { error: 'Bad request' });
  }
}

http.createServer(handle).listen(PORT, () => {
  console.log(`MyVids running at http://localhost:${PORT}  (data in ${DATA_DIR})`);
});
