require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const QRCode = require('qrcode');
const { authenticator } = require('otplib');

const pool = require('./db');
const { encrypt, decrypt } = require('./crypto-util');

authenticator.options = { window: 1 }; // 前後30秒の時刻ずれを許容

const app = express();
const isProd = process.env.NODE_ENV === 'production';
if (isProd) app.set('trust proxy', 1);

app.use(helmet());
app.use(express.json());
app.use(
  session({
    store: new PgSession({ pool, tableName: 'session', createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: 'sid',
    cookie: {
      httpOnly: true,
      sameSite: 'strict', // CSRF 対策
      secure: isProd,     // 本番は HTTPS 必須
      maxAge: 1000 * 60 * 60 * 2,
    },
  })
);
app.use(express.static(path.join(__dirname, 'public')));

// ブルートフォース対策
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });

const requireAuth = (req, res, next) =>
  req.session.userId ? next() : res.status(401).json({ error: 'ログインが必要です' });

// session.regenerate を Promise 化 (セッション固定攻撃対策)
const regenerate = (req) => new Promise((resolve, reject) => req.session.regenerate((e) => (e ? reject(e) : resolve())));

const DUMMY_HASH = bcrypt.hashSync('dummy-password', 12); // ユーザー存在判定のタイミング差を減らす

/* ---------- 新規登録 ---------- */
app.post('/api/register', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  console.log(req.body)
  
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: 'メールアドレスが不正です' });
  }
  if (!password || password.length < 6) {
    console.log('パスワードは6文字以上にしてください');  
    return res.status(400).json({ error: 'パスワードは6文字以上にしてください' });
  } 
  try {
    const hash = await bcrypt.hash(password, 12);
    await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email.toLowerCase(), hash]);
    res.json({ ok: true });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: '登録済みのメールアドレスです' });
    console.error(e);
    res.status(500).json({ error: 'サーバーエラー' });
  }
});

/* ---------- ログイン (1段階目: パスワード) ---------- */
app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [String(email || '').toLowerCase()]);
    const user = rows[0];
    const ok = await bcrypt.compare(String(password || ''), user ? user.password_hash : DUMMY_HASH);
    if (!user || !ok) return res.status(401).json({ error: 'メールアドレスまたはパスワードが違います' });

    await regenerate(req);
    if (user.totp_enabled) {
      req.session.pending2faUserId = user.id; // まだログイン完了ではない
      req.session.pendingAt = Date.now();
      return res.json({ need2fa: true });
    }
    req.session.userId = user.id;
    res.json({ ok: true, need2fa: false });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'サーバーエラー' });
  }
});

/* ---------- ログイン (2段階目: OTP) ---------- */
app.post('/api/login/2fa', authLimiter, async (req, res) => {
  const { token } = req.body || {};
  const uid = req.session.pending2faUserId;
  if (!uid || Date.now() - (req.session.pendingAt || 0) > 5 * 60 * 1000) {
    return res.status(401).json({ error: '先にパスワード認証を行ってください' });
  }
  try {
    const { rows } = await pool.query('SELECT totp_secret FROM users WHERE id = $1 AND totp_enabled = TRUE', [uid]);
    if (!rows[0]) return res.status(401).json({ error: '認証できません' });

    const secret = decrypt(rows[0].totp_secret);
    if (!/^\d{6}$/.test(String(token)) || !authenticator.check(String(token), secret)) {
      return res.status(401).json({ error: 'ワンタイムパスワードが違います' });
    }
    await regenerate(req);
    req.session.userId = uid;
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'サーバーエラー' });
  }
});

/* ---------- 2FA 設定: シークレット発行 + QR コード ---------- */
app.post('/api/2fa/setup', requireAuth, async (req, res) => {
  try {
    console.log("APP_NAME=", process.env.APP_NAME)
    const { rows } = await pool.query('SELECT email, totp_enabled FROM users WHERE id = $1', [req.session.userId]);
    if (rows[0].totp_enabled) return res.status(400).json({ error: '2FA は既に有効です' });

    const secret = authenticator.generateSecret();
    req.session.tempTotpSecret = secret; // 確認が済むまで DB には保存しない
    const otpauth = authenticator.keyuri(rows[0].email, process.env.APP_NAME || 'MyWebApp', secret);
    const qr = await QRCode.toDataURL(otpauth);
    res.json({ qr, secret }); // secret は QR を読めない時の手入力用
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'サーバーエラー' });
  }
});

/* ---------- 2FA 設定: アプリの6桁コードで有効化 ---------- */
app.post('/api/2fa/enable', requireAuth, async (req, res) => {
  const { token } = req.body || {};
  const secret = req.session.tempTotpSecret;
  if (!secret) return res.status(400).json({ error: '先に設定を開始してください' });
  if (!authenticator.check(String(token), secret)) return res.status(400).json({ error: 'コードが違います' });
  try {
    await pool.query('UPDATE users SET totp_secret = $1, totp_enabled = TRUE WHERE id = $2', [
      encrypt(secret),
      req.session.userId,
    ]);
    delete req.session.tempTotpSecret;
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'サーバーエラー' });
  }
});

/* ---------- 2FA 無効化 (パスワード + OTP 再確認) ---------- */
app.post('/api/2fa/disable', requireAuth, authLimiter, async (req, res) => {
  const { password, token } = req.body || {};
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.userId]);
    const u = rows[0];
    if (!u.totp_enabled) return res.status(400).json({ error: '2FA は無効です' });
    const okPw = await bcrypt.compare(String(password || ''), u.password_hash);
    const okOtp = authenticator.check(String(token), decrypt(u.totp_secret));
    if (!okPw || !okOtp) return res.status(401).json({ error: 'パスワードまたはコードが違います' });
    await pool.query('UPDATE users SET totp_secret = NULL, totp_enabled = FALSE WHERE id = $1', [u.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'サーバーエラー' });
  }
});

/* ---------- ユーザー情報 / ログアウト ---------- */
app.get('/api/me', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT email, totp_enabled FROM users WHERE id = $1', [req.session.userId]);
  res.json(rows[0]);
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.json({ ok: true });
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`http://localhost:${port}`));
