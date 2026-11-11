
const enc = new TextEncoder();
const ITER = 60000;
const SESSION_MS = 30 * 864e5;
const ADMIN = 'admin';
const COL_RE = /^[A-Za-z0-9' \-]{1,30}$/;

const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
const rand = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const json = (o, s = 200) => new Response(JSON.stringify(o), {
  status: s,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }
});
const err = (m, s = 400) => json({ error: m }, s);

const int = (v, min, max) => { v = Math.floor(Number(v)); if (!Number.isFinite(v)) v = min; return Math.max(min, Math.min(max, v)); };
const num = (v, min, max) => { v = Number(v); if (!Number.isFinite(v)) v = 0; return Math.max(min, Math.min(max, v)); };
const clean = (s, n) => String(s == null ? '' : s).replace(/[<>&"'`]/g, '').slice(0, n);

async function hashPass(pass, saltHex, iter) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unhex(saltHex), iterations: iter }, key, 256);
  return hex(bits);
}
function same(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

let ready = false;
async function init(db) {
  if (ready) return;
  await db.exec('CREATE TABLE IF NOT EXISTS attempts (k TEXT PRIMARY KEY, n INTEGER NOT NULL, ts INTEGER NOT NULL)');
  await db.exec("CREATE TABLE IF NOT EXISTS bans (user_id INTEGER PRIMARY KEY, reason TEXT NOT NULL DEFAULT '', ts INTEGER NOT NULL)");
  await db.exec('CREATE TABLE IF NOT EXISTS grants (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, ts INTEGER NOT NULL, applied INTEGER NOT NULL DEFAULT 0)');
  await db.exec('CREATE INDEX IF NOT EXISTS grants_u ON grants (user_id, applied)');
  await db.exec('CREATE TABLE IF NOT EXISTS admin_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, admin TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL)');
  await db.exec('CREATE TABLE IF NOT EXISTS tglink (user_id INTEGER PRIMARY KEY, tg_id INTEGER NOT NULL UNIQUE, ts INTEGER NOT NULL)');
  await db.exec('CREATE TABLE IF NOT EXISTS cronat (user_id INTEGER PRIMARY KEY, at INTEGER NOT NULL)');
  await db.exec('CREATE TABLE IF NOT EXISTS listings (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, col TEXT NOT NULL, serial INTEGER NOT NULL, price REAL NOT NULL, gid INTEGER NOT NULL DEFAULT 0, vcap REAL NOT NULL DEFAULT 0, vmul REAL NOT NULL DEFAULT 0, ts INTEGER NOT NULL, UNIQUE (user_id, col, serial))');
  await db.exec('CREATE INDEX IF NOT EXISTS listings_ts ON listings (ts)');
  ready = true;
}

const BOTS = ['@whale_gram', '@pepe_hunter', '@durov_vault', '@fragment_sniper', '@flip_master', '@portals_arb', '@tokyo_drift', '@gift_baron', '@vice_runner', '@lucia_flips'];
const pick = a => a[Math.floor(Math.random() * a.length)];
const f2 = n => (Math.round(n * 100) / 100).toFixed(2);

function appLink(env, start) {
  const bot = String(env.BOT_USERNAME || '').replace(/^@/, '');
  if (!/^[A-Za-z0-9_]{3,40}$/.test(bot)) return '';
  const sh = String(env.APP_SHORTNAME || '');
  return 'https://t.me/' + bot + (/^[A-Za-z0-9_]{1,40}$/.test(sh) ? '/' + sh : '') + (start ? '?startapp=' + encodeURIComponent(start) : '');
}
async function tgSend(env, chatId, text) {
  if (!env.BOT_TOKEN || !chatId) return false;
  const link = appLink(env, 'open');
  try {
    const r = await fetch('https://api.telegram.org/bot' + env.BOT_TOKEN + '/sendMessage', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true, reply_markup: link ? { inline_keyboard: [[{ text: 'Открыть Portals Market', url: link }]] } : undefined })
    });
    return r.ok;
  } catch (e) { return false; }
}
async function checkInit(initData, token) {
  if (!token || typeof initData !== 'string' || initData.length > 4096) return null;
  const p = new URLSearchParams(initData), hash = p.get('hash');
  if (!hash) return null;
  p.delete('hash');
  const dcs = [...p.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)).map(([k, v]) => k + '=' + v).join('\n');
  const k1 = await crypto.subtle.importKey('raw', enc.encode('WebAppData'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const secret = await crypto.subtle.sign('HMAC', k1, enc.encode(token));
  const k2 = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = hex(await crypto.subtle.sign('HMAC', k2, enc.encode(dcs)));
  if (!same(sig, hash)) return null;
  if (Date.now() / 1000 - Number(p.get('auth_date') || 0) > 7 * 86400) return null;
  let u = null; try { u = JSON.parse(p.get('user') || 'null'); } catch (e) {}
  return u && Number.isInteger(u.id) && u.id > 0 ? u : null;
}

async function limited(db, key, max, windowMs) {
  const now = Date.now();
  const r = await db.prepare('SELECT n, ts FROM attempts WHERE k = ?').bind(key).first();
  if (r && now - r.ts < windowMs) {
    if (r.n >= max) return true;
    await db.prepare('UPDATE attempts SET n = n + 1 WHERE k = ?').bind(key).run();
    return false;
  }
  await db.prepare('INSERT OR REPLACE INTO attempts (k, n, ts) VALUES (?, 1, ?)').bind(key, now).run();
  return false;
}

async function readJson(req, limit = 4000) {
  const t = await req.text();
  if (t.length > limit) throw new Error('big');
  return JSON.parse(t);
}

async function auth(req, env) {
  const m = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.get('authorization') || '');
  if (!m) return null;
  const row = await env.DB.prepare(
    'SELECT u.id, u.username, s.created, b.reason AS ban_reason, (b.user_id IS NOT NULL) AS banned ' +
    'FROM sessions s JOIN users u ON u.id = s.user_id LEFT JOIN bans b ON b.user_id = u.id WHERE s.token = ?'
  ).bind(await sha(m[1])).first();
  if (!row || Date.now() - row.created > SESSION_MS) return null;
  return row;
}
const banMsg = r => 'Аккаунт заблокирован' + (r && r.length ? ': ' + r : '');

async function authed(req, env) {
  const u = await auth(req, env);
  if (!u) return { res: err('Нужно войти', 401) };
  if (u.banned) return { res: err(banMsg(u.ban_reason), 403) };
  return { u };
}

async function newSession(env, userId) {
  const token = rand(32);
  const now = Date.now();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND created < ?').bind(userId, now - SESSION_MS).run();
  await env.DB.prepare('INSERT INTO sessions (token, user_id, created) VALUES (?, ?, ?)').bind(await sha(token), userId, now).run();
  return token;
}

const USER_RE = /^[A-Za-z0-9_]{3,20}$/;

async function register(req, env) {
  let b; try { b = await readJson(req); } catch (e) { return err('Неверный запрос'); }
  const username = String(b.username || '').trim(), password = String(b.password || '');
  if (!USER_RE.test(username)) return err('Юзернейм: 3–20 символов, латиница, цифры и _');
  if (username !== ADMIN && username.toLowerCase() === ADMIN) return err('Этот юзернейм зарезервирован', 409);
  if (password.length < 6 || password.length > 100) return err('Пароль: от 6 до 100 символов');
  const ip = req.headers.get('CF-Connecting-IP') || 'x';
  if (await limited(env.DB, 'reg:' + ip, 5, 3600000)) return err('Слишком много регистраций. Попробуйте позже', 429);
  if (await env.DB.prepare('SELECT 1 AS x FROM users WHERE username = ?').bind(username).first()) return err('Этот юзернейм уже занят', 409);
  const salt = rand(16), h = await hashPass(password, salt, ITER);
  let id;
  try {
    const r = await env.DB.prepare('INSERT INTO users (username, pass_hash, salt, created) VALUES (?, ?, ?, ?)')
      .bind(username, ITER + '$' + h, salt, Date.now()).run();
    id = r.meta.last_row_id;
  } catch (e) { return err('Этот юзернейм уже занят', 409); }
  return json({ token: await newSession(env, id), username });
}

async function login(req, env) {
  let b; try { b = await readJson(req); } catch (e) { return err('Неверный запрос'); }
  const username = String(b.username || '').trim(), password = String(b.password || '');
  if (!USER_RE.test(username) || !password || password.length > 100) return err('Неверный юзернейм или пароль', 401);
  const ip = req.headers.get('CF-Connecting-IP') || 'x';
  const uk = 'loginu:' + username.toLowerCase();
  if (await limited(env.DB, 'login:' + ip, 20, 600000) || await limited(env.DB, uk, 10, 600000))
    return err('Слишком много попыток входа. Подождите 10 минут', 429);
  const u = await env.DB.prepare('SELECT id, username, pass_hash, salt FROM users WHERE username = ?').bind(username).first();
  if (!u) { await hashPass(password, '00'.repeat(16), ITER); return err('Неверный юзернейм или пароль', 401); }
  const [it, stored] = String(u.pass_hash).split('$');
  const got = await hashPass(password, u.salt, int(it, 1000, 100000));
  if (!same(got, stored || '')) return err('Неверный юзернейм или пароль', 401);
  await env.DB.prepare('DELETE FROM attempts WHERE k = ?').bind(uk).run();
  const ban = await env.DB.prepare('SELECT reason FROM bans WHERE user_id = ?').bind(u.id).first();
  if (ban) return err(banMsg(ban.reason), 403);
  return json({ token: await newSession(env, u.id), username: u.username });
}

function buildProfile(d, worth) {
  const p = d.prof || {};
  const inv = d.inv.filter(g => g && !g.base && typeof g.col === 'string');
  const toG = g => ({ col: clean(g.col, 30), serial: int(g.serial, 1, 1000000), mi: int(g.mi, 0, 7), bi: int(g.bi, 0, 18), pi: int(g.pi, 0, 8) });
  const byId = new Map(inv.map(g => [g.id, g]));
  const pins = (Array.isArray(d.pinned) ? d.pinned : []).map(id => byId.get(id)).filter(Boolean);
  const w = byId.get(d.worn);
  return {
    name: clean(p.name, 24) || 'Трейдер',
    bio: clean(p.bio, 70),
    col: int(p.col, 0, 5),
    worn: w ? toG(w) : null,
    gifts: (pins.length ? pins : inv).slice(0, 9).map(toG),
    count: inv.length,
    stats: {
      profit: num(d.profit, -1e7, 1e7), flips: int(d.flips, 0, 1e7), best: num(d.best, -1e7, 1e7),
      vol: num(d.vol, 0, 1e9), spent: num(d.spent, 0, 1e9)
    },
    worth: num(worth, 0, 1e9),
    ev: int(d.ev && d.ev.earned, 0, 1e7),
    vc: d.ev && d.ev.badge ? 1 : 0
  };
}

async function save(req, env, user) {
  const text = await req.text();
  if (text.length > 600000) return err('Сохранение слишком большое', 413);
  let b; try { b = JSON.parse(text); } catch (e) { return err('Неверный формат'); }
  const d = b && b.data;
  if (!d || typeof d !== 'object' || !Number.isFinite(d.ton) || !Array.isArray(d.inv) || !Array.isArray(d.market)) return err('Неверные данные');
  if (d.inv.length > 400 || d.market.length > 400) return err('Слишком много подарков', 413);
  if (d.ton < 0 || d.ton > 1e6) return err('Недопустимый баланс', 409);

  const now = Date.now();
  const prev = await env.DB.prepare('SELECT data, updated FROM saves WHERE user_id = ?').bind(user.id).first();
  if (prev && now - prev.updated < 1500) return err('Слишком часто', 429);
  if (prev) { const pd = parse(prev.data); if (pd && (Number(pd.rev) || 0) > (Number(d.rev) || 0)) return err('stale', 409); }

  let ack = [];
  if (Array.isArray(b.ack)) ack = [...new Set(b.ack.map(Number).filter(n => Number.isInteger(n) && n > 0))].slice(0, 50);
  let gr = [];
  if (ack.length) {
    const q = await env.DB.prepare(
      'SELECT id, kind, payload FROM grants WHERE user_id = ? AND applied = 0 AND id IN (' + ack.map(() => '?').join(',') + ')'
    ).bind(user.id, ...ack).all();
    gr = q.results || [];
  }
  let tonCredit = 0;
  for (const r of gr) if (r.kind === 'ton') { const p = parse(r.payload) || {}; if (p.amount > 0) tonCredit += p.amount; }


  {
    const rs = await env.DB.prepare("SELECT id FROM grants WHERE user_id = ? AND applied = 0 AND kind = 'reset-stats'").bind(user.id).all();
    if ((rs.results || []).some(r => !ack.includes(r.id))) { d.profit = 0; d.flips = 0; d.best = 0; d.vol = 0; d.spent = 0; }
  }

  const profile = JSON.stringify(buildProfile(d, b.worth));
  const stmts = [env.DB.prepare(
    'INSERT INTO saves (user_id, data, profile, updated) VALUES (?, ?, ?, ?) ' +
    'ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, profile = excluded.profile, updated = excluded.updated'
  ).bind(user.id, JSON.stringify(d), profile, now)];
  for (const r of gr) stmts.push(env.DB.prepare('UPDATE grants SET applied = 1 WHERE id = ? AND user_id = ?').bind(r.id, user.id));
  await env.DB.batch(stmts);
  // лоты, которых больше нет в списке выставленных подарков игрока, снимаем (с запасом 20 с на гонки)
  try {
    const mine = await env.DB.prepare('SELECT id, col, serial, ts FROM listings WHERE user_id = ?').bind(user.id).all();
    if ((mine.results || []).length) {
      const listed = new Set(d.inv.filter(g => g && !g.base && g.listed).map(g => g.col + '#' + Number(g.serial)));
      const dead = mine.results.filter(r => now - r.ts > 20000 && !listed.has(r.col + '#' + r.serial)).map(r => r.id);
      if (dead.length) await env.DB.prepare('DELETE FROM listings WHERE user_id = ? AND id IN (' + dead.map(() => '?').join(',') + ')').bind(user.id, ...dead).run();
    }
  } catch (e) {}
  return json({ ok: true, t: now });
}

async function transfer(req, env, u) {
  let b; try { b = await readJson(req); } catch (e) { return err('Неверный запрос'); }
  const t = await findUser(env, b.user);
  if (!t) return err('Игрок не найден', 404);
  if (t.id === u.id) return err('Нельзя передать подарок самому себе');
  if (await env.DB.prepare('SELECT 1 AS x FROM bans WHERE user_id = ?').bind(t.id).first()) return err('Этот игрок заблокирован');
  const col = String(b.col || '');
  if (!COL_RE.test(col)) return err('Неверная коллекция');
  const serial = int(b.serial, 1, 1000000);
  if (await limited(env.DB, 'xfer:' + u.id, 40, 3600000)) return err('Слишком много передач. Попробуйте позже', 429);
  const row = await env.DB.prepare('SELECT data, profile FROM saves WHERE user_id = ?').bind(u.id).first();
  const d = row && parse(row.data);
  const i = d && Array.isArray(d.inv) ? d.inv.findIndex(g => g && !g.base && g.col === col && Number(g.serial) === serial) : -1;
  if (i < 0) return err('Подарок не найден в сохранении. Подождите пару секунд и повторите');
  const gid = d.inv[i].id, vcap = num(d.inv[i].vcap, 0, 1e7), vmul = num(d.inv[i].vmul, 0, 1000);
  // если подарок выставлен игрокам — сначала снимаем лот; если его уже купили, отправка отменяется
  const lst = await takeListing(env, u.id, col, serial);
  if (lst === 'sold') return err('Подарок уже продан');
  d.inv.splice(i, 1);
  d.market = (d.market || []).filter(g => !(g && g.id === gid));
  d.pinned = (d.pinned || []).filter(x => x !== gid);
  d.offers = (d.offers || []).filter(o => !(o && o.gid === gid));
  if (d.worn === gid) d.worn = null;
  const worth = (parse(row.profile) || {}).worth || 0;
  await env.DB.batch([
    env.DB.prepare('UPDATE saves SET data = ?, profile = ? WHERE user_id = ?').bind(JSON.stringify(d), JSON.stringify(buildProfile(d, worth)), u.id),
    env.DB.prepare('INSERT INTO grants (user_id, kind, payload, ts) VALUES (?, ?, ?, ?)').bind(t.id, 'gift', JSON.stringify({ col, serial, from: u.username, vcap, vmul }), Date.now())
  ]);
  await adminLog(env, u.username, 'transfer', t.username, col + ' #' + serial);
  return json({ ok: true });
}

const parse = s => { try { return JSON.parse(s); } catch (e) { return null; } };

async function pendingGrants(env, userId) {
  const { results } = await env.DB.prepare(
    'SELECT id, kind, payload FROM grants WHERE user_id = ? AND applied = 0 ORDER BY id LIMIT 50'
  ).bind(userId).all();
  return results.map(r => Object.assign({ id: r.id, kind: r.kind }, parse(r.payload) || {}));
}

async function findUser(env, name) {
  name = String(name || '');
  if (!USER_RE.test(name)) return null;
  return env.DB.prepare('SELECT id, username FROM users WHERE username = ?').bind(name).first();
}
async function adminLog(env, admin, action, target, detail) {
  await env.DB.prepare('INSERT INTO admin_log (ts, admin, action, target, detail) VALUES (?, ?, ?, ?, ?)')
    .bind(Date.now(), admin, action, target, String(detail).slice(0, 300)).run();
}

async function adminRoute(req, env, url, path, m, u) {
  if (u.username !== ADMIN) return err('Нет доступа', 403);

  if (path === '/api/admin/users' && m === 'GET') {
    const q = (url.searchParams.get('q') || '').replace(/^@/, '');
    if (!/^[A-Za-z0-9_]{0,20}$/.test(q)) return json({ users: [] });
    const like = '%' + q.replace(/[\\%_]/g, '\\$&') + '%';
    const { results } = await env.DB.prepare(
      'SELECT u.username, s.profile, s.updated, b.reason AS ban_reason, (b.user_id IS NOT NULL) AS banned ' +
      'FROM users u LEFT JOIN saves s ON s.user_id = u.id LEFT JOIN bans b ON b.user_id = u.id ' +
      "WHERE u.username LIKE ? ESCAPE '\\' ORDER BY (lower(u.username) = lower(?)) DESC, s.updated DESC LIMIT 25"
    ).bind(like, q).all();
    return json({
      users: results.map(r => {
        const p = parse(r.profile) || {}, st = p.stats || {};
        return {
          username: r.username, name: p.name || r.username, worth: p.worth || 0, profit: st.profit || 0,
          count: p.count || 0, ev: p.ev || 0, seen: r.updated || 0, banned: !!r.banned, reason: r.ban_reason || ''
        };
      })
    });
  }

  if (m !== 'POST') return err('Не найдено', 404);
  let b; try { b = await readJson(req); } catch (e) { return err('Неверный запрос'); }
  const t = await findUser(env, b.user);
  if (!t) return err('Игрок не найден', 404);

  if (path === '/api/admin/ban') {
    if (t.username === ADMIN) return err('Нельзя заблокировать администратора');
    if (b.ban) {
      const reason = clean(b.reason, 100);
      await env.DB.prepare('INSERT OR REPLACE INTO bans (user_id, reason, ts) VALUES (?, ?, ?)').bind(t.id, reason, Date.now()).run();
      await adminLog(env, u.username, 'ban', t.username, reason);
    } else {
      await env.DB.prepare('DELETE FROM bans WHERE user_id = ?').bind(t.id).run();
      await adminLog(env, u.username, 'unban', t.username, '');
    }
    return json({ ok: true, banned: !!b.ban });
  }

  if (path === '/api/admin/reset-stats') {
    const row = await env.DB.prepare('SELECT data, profile FROM saves WHERE user_id = ?').bind(t.id).first();
    const stmts = [env.DB.prepare('INSERT INTO grants (user_id, kind, payload, ts) VALUES (?, ?, ?, ?)')
      .bind(t.id, 'reset-stats', '{}', Date.now())];
    const d = row && parse(row.data);
    if (d && typeof d === 'object') {
      d.profit = 0; d.flips = 0; d.best = 0; d.vol = 0; d.spent = 0;
      const worth = (parse(row.profile) || {}).worth || 0;
      stmts.push(env.DB.prepare('UPDATE saves SET data = ?, profile = ? WHERE user_id = ?')
        .bind(JSON.stringify(d), JSON.stringify(buildProfile(d, worth)), t.id));
    }
    await env.DB.batch(stmts);
    await adminLog(env, u.username, 'reset-stats', t.username, '');
    return json({ ok: true });
  }

  if (path === '/api/admin/give-ton') {
    const amount = Math.round(Number(b.amount) * 100) / 100;
    if (!Number.isFinite(amount) || amount === 0 || Math.abs(amount) > 500000) return err('Сумма: от 0.01 до 500000 GRAM (можно со знаком минус)');
    await env.DB.prepare('INSERT INTO grants (user_id, kind, payload, ts) VALUES (?, ?, ?, ?)')
      .bind(t.id, 'ton', JSON.stringify({ amount }), Date.now()).run();
    await adminLog(env, u.username, 'give-ton', t.username, amount);
    return json({ ok: true });
  }

  if (path === '/api/admin/give-stars') {
    const amount = Math.round(Number(b.amount));
    if (!Number.isFinite(amount) || amount === 0 || Math.abs(amount) > 1000000) return err('Количество: от 1 до 1000000');
    await env.DB.prepare('INSERT INTO grants (user_id, kind, payload, ts) VALUES (?, ?, ?, ?)')
      .bind(t.id, 'stars', JSON.stringify({ amount }), Date.now()).run();
    await adminLog(env, u.username, 'give-stars', t.username, amount);
    return json({ ok: true });
  }

  if (path === '/api/admin/give-gift') {
    const col = String(b.col || '');
    if (!COL_RE.test(col)) return err('Неверная коллекция');
    const serial = int(b.serial, 0, 1000000);
    await env.DB.prepare('INSERT INTO grants (user_id, kind, payload, ts) VALUES (?, ?, ?, ?)')
      .bind(t.id, 'gift', JSON.stringify({ col, serial }), Date.now()).run();
    await adminLog(env, u.username, 'give-gift', t.username, col + ' #' + serial);
    return json({ ok: true });
  }

  return err('Не найдено', 404);
}

async function tglink(req, env, u) {
  if (!env.BOT_TOKEN) return json({ linked: false, off: true });
  let b; try { b = await readJson(req, 6000); } catch (e) { return err('Неверный запрос'); }
  const t = await checkInit(b.initData, env.BOT_TOKEN);
  if (!t) return err('Не удалось проверить Telegram', 401);
  const now = Date.now();
  const other = await env.DB.prepare('SELECT user_id FROM tglink WHERE tg_id = ?').bind(t.id).first();
  if (other && other.user_id !== u.id) return json({ linked: false, busy: true });
  if (!other) {
    await env.DB.prepare('INSERT OR REPLACE INTO tglink (user_id, tg_id, ts) VALUES (?, ?, ?)').bind(u.id, t.id, now).run();
  }
  return json({ linked: true });
}

async function cron(env) {
  await init(env.DB);
  const now = Date.now();
  const { results } = await env.DB.prepare(
    'SELECT s.user_id, s.data, s.profile, s.updated, t.tg_id, c.at FROM saves s LEFT JOIN tglink t ON t.user_id = s.user_id LEFT JOIN cronat c ON c.user_id = s.user_id ' +
    'WHERE s.updated < ? AND s.updated > ? AND NOT EXISTS (SELECT 1 FROM bans b WHERE b.user_id = s.user_id) ORDER BY s.updated DESC LIMIT 300'
  ).bind(now - 4 * 60e3, now - 14 * 864e5).all();
  const marks = [];
  for (const row of results) {
    const d = parse(row.data);
    if (!d || !Array.isArray(d.inv) || !Number.isFinite(d.ton)) continue;
    const last = Math.max(row.at || 0, row.updated || 0), mins = Math.min(120, (now - last) / 60e3);
    marks.push(env.DB.prepare('INSERT OR REPLACE INTO cronat (user_id, at) VALUES (?, ?)').bind(row.user_id, now));
    if (mins < 1) continue;
    const msgs = [], away = [];
    let changed = false;
    for (const g of [...d.inv]) {
      if (!g || g.base || !g.listed || !(g.price > 0)) continue;
      const ch = num(g.ch, 0, 0.5);
      if (!ch || Math.random() >= 1 - Math.pow(1 - ch, 7 * mins)) continue;
      // если подарок выставлен игрокам, продаём боту только когда лот удалось забрать (иначе его уже купил игрок)
      if (g.sl) {
        const tk = await env.DB.prepare('DELETE FROM listings WHERE user_id = ? AND col = ? AND serial = ?').bind(row.user_id, g.col, int(g.serial, 0, 1000000)).run();
        if (!(tk.meta && tk.meta.changes > 0)) continue;
      }
      const vol = +d.vol || 0, fee = g.ncap > 0 ? 0 : vol >= 500 ? 0.03 : vol >= 100 ? 0.04 : 0.05;
      const net = +(g.price * (1 - fee)).toFixed(2), pl = +(net - (+g.bought || 0)).toFixed(2);
      d.inv = d.inv.filter(x => x !== g);
      d.market = (d.market || []).filter(x => !(x && x.id === g.id));
      d.pinned = (d.pinned || []).filter(x => x !== g.id);
      d.offers = (d.offers || []).filter(o => !(o && o.gid === g.id));
      if (d.worn === g.id) d.worn = null;
      d.ton = +Math.min(1e6, d.ton + net).toFixed(2);
      if (!g.gr) { d.profit = +((+d.profit || 0) + pl).toFixed(2); d.flips = (d.flips | 0) + 1; if (pl > (+d.best || 0)) d.best = pl; }
      d.vol = +(vol + g.price).toFixed(2);
      d.hist = [{ t: 'Продажа ' + g.col + ' #' + g.serial, a: '+' + f2(net), c: 'emerald', time: now }, ...(Array.isArray(d.hist) ? d.hist : [])].slice(0, 60);
      const line = g.col + ' #' + g.serial + ' купили за ' + f2(g.price) + ' GRAM (' + (pl >= 0 ? '+' : '') + f2(pl) + ')';
      msgs.push('Твой ' + line); away.push('Продано: ' + line);
      changed = true;
    }
    d.offers = (Array.isArray(d.offers) ? d.offers : []).filter(o => o && o.exp > now);
    const cand = d.inv.filter(g => g && !g.base && g.fv > 0 && !d.offers.some(o => o.gid === g.id));
    if (cand.length && d.offers.length < 4 && Math.random() < 0.12 * Math.min(4, mins / 5)) {
      const g = pick(cand), bot = pick(BOTS), price = +(num(g.fv, 0, 1e7) * (0.84 + Math.random() * 0.16)).toFixed(2);
      d.offers.unshift({ oid: now + Math.floor(Math.random() * 999), gid: g.id, bot, price, exp: now + 3600e3 });
      msgs.push('Новый оффер: ' + bot + ' предлагает ' + f2(price) + ' GRAM за ' + g.col + ' #' + g.serial + '. Оффер действует час.');
      away.push('Новый оффер на ' + g.col + ' #' + g.serial);
      changed = true;
    }
    if (d.wheelAt > 0 && now >= d.wheelAt + 864e5 && !d.wn) {
      d.wn = 1; changed = true;
      msgs.push('Колесо удачи снова доступно — крути бесплатно!');
    }
    if (!changed) continue;
    d.rev = (Number(d.rev) || 0) + 1;
    d.away = [...(Array.isArray(d.away) ? d.away : []), ...away].slice(-10);
    const worth = (parse(row.profile) || {}).worth || 0;
    await env.DB.prepare('UPDATE saves SET data = ?, profile = ? WHERE user_id = ?').bind(JSON.stringify(d), JSON.stringify(buildProfile(d, worth)), row.user_id).run();
    if (row.tg_id && d.notif !== false && msgs.length) {
      const text = msgs.length > 3 ? msgs.slice(0, 3).join('\n') + '\nи ещё ' + (msgs.length - 3) + '…' : msgs.join('\n\n');
      await tgSend(env, row.tg_id, text);
    }
  }
  for (let i = 0; i < marks.length; i += 50) await env.DB.batch(marks.slice(i, i + 50));
}

/* ───────── Общий рынок игроков ─────────
   Это отдельный слой поверх симуляции: боты, флоры, шансы и цены считаются на клиенте как раньше.
   Сервер отвечает только за то, чтобы один подарок нельзя было продать дважды. */
const SALE_PENDING = "SELECT 1 AS x FROM grants WHERE user_id = ? AND kind = 'sale' AND applied = 0 AND json_extract(payload, '$.col') = ? AND json_extract(payload, '$.serial') = ?";

// Забрать лот с рынка. 'taken' — лот был и удалён; 'sold' — его уже купил игрок (награда ждёт продавца); 'none' — лота не было.
async function takeListing(env, uid, col, serial) {
  const r = await env.DB.prepare('DELETE FROM listings WHERE user_id = ? AND col = ? AND serial = ?').bind(uid, col, serial).run();
  if (r.meta && r.meta.changes > 0) return 'taken';
  const s = await env.DB.prepare(SALE_PENDING).bind(uid, col, serial).first();
  return s ? 'sold' : 'none';
}

async function savedGift(env, uid, col, serial) {
  const row = await env.DB.prepare('SELECT data FROM saves WHERE user_id = ?').bind(uid).first();
  const d = row && parse(row.data);
  if (!d || !Array.isArray(d.inv)) return null;
  const g = d.inv.find(x => x && !x.base && x.col === col && Number(x.serial) === serial);
  return g ? { g, d } : null;
}

async function marketList(req, env, u) {
  let b; try { b = await readJson(req); } catch (e) { return err('Неверный запрос'); }
  const col = String(b.col || '');
  if (!COL_RE.test(col)) return err('Неверная коллекция');
  const serial = int(b.serial, 1, 1000000);
  const price = Math.round(num(b.price, 0, 1e6) * 100) / 100;
  if (!(price >= 0.5)) return err('Неверная цена');
  if (await limited(env.DB, 'mkl:' + u.id, 400, 3600000)) return err('Слишком часто. Попробуйте позже', 429);
  if (await env.DB.prepare(SALE_PENDING).bind(u.id, col, serial).first()) return err('Подарок уже продан', 409);
  const sg = await savedGift(env, u.id, col, serial);
  if (!sg) return err('Подарок не найден в сохранении. Подождите пару секунд и повторите', 409);
  const ex = await env.DB.prepare('SELECT id FROM listings WHERE user_id = ? AND col = ? AND serial = ?').bind(u.id, col, serial).first();
  if (!ex) {
    const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM listings WHERE user_id = ?').bind(u.id).first();
    if (c && c.n >= 100) return err('Не больше 100 лотов одновременно', 409);
  }
  const vcap = num(sg.g.vcap, 0, 1e7), vmul = num(sg.g.vmul, 0, 1000);
  await env.DB.prepare(
    'INSERT INTO listings (user_id, col, serial, price, gid, vcap, vmul, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(user_id, col, serial) DO UPDATE SET price = excluded.price, gid = excluded.gid, vcap = excluded.vcap, vmul = excluded.vmul'
  ).bind(u.id, col, serial, price, int(b.gid, 0, 1e9), vcap, vmul, Date.now()).run();
  return json({ ok: true });
}

// unlist и claim: оба забирают лот, claim используется перед продажей боту/офферу
async function marketTake(req, env, u) {
  let b; try { b = await readJson(req); } catch (e) { return err('Неверный запрос'); }
  const col = String(b.col || '');
  if (!COL_RE.test(col)) return err('Неверная коллекция');
  const st = await takeListing(env, u.id, col, int(b.serial, 1, 1000000));
  return json({ ok: st !== 'sold', gone: st === 'sold' });
}

async function marketBuy(req, env, u) {
  let b; try { b = await readJson(req); } catch (e) { return err('Неверный запрос'); }
  const id = int(b.id, 0, 1e12);
  if (await limited(env.DB, 'mkb:' + u.id, 150, 600000)) return err('Слишком часто. Попробуйте позже', 429);
  const row = await env.DB.prepare(
    'SELECT l.id, l.user_id, l.col, l.serial, l.price, l.vcap, l.vmul, s.username AS seller, (b.user_id IS NOT NULL) AS banned ' +
    'FROM listings l JOIN users s ON s.id = l.user_id LEFT JOIN bans b ON b.user_id = l.user_id WHERE l.id = ?'
  ).bind(id).first();
  if (!row) return err('Лот уже продан или снят', 409);
  if (row.user_id === u.id) return err('Это ваш лот', 409);
  if (row.banned) { await env.DB.prepare('DELETE FROM listings WHERE id = ?').bind(row.id).run(); return err('Лот недоступен', 409); }
  if (Math.abs(row.price - Number(b.price)) > 0.001) return err('Цена изменилась: теперь ' + f2(row.price) + ' GRAM', 409);
  // лот должен реально существовать в сохранении продавца (защита от дублей и «призрачных» лотов)
  const sg = await savedGift(env, row.user_id, row.col, row.serial);
  if (!sg) { await env.DB.prepare('DELETE FROM listings WHERE id = ?').bind(row.id).run(); return err('Лот недоступен', 409); }

  const now = Date.now();
  const gp = JSON.stringify({ col: row.col, serial: row.serial, from: row.seller, vcap: row.vcap, vmul: row.vmul, paid: row.price, mk: 1 });
  const sp = JSON.stringify({ col: row.col, serial: row.serial, price: row.price, buyer: u.username });
  const cond = ' WHERE EXISTS (SELECT 1 FROM listings WHERE id = ? AND price = ?)';
  const res = await env.DB.batch([
    env.DB.prepare('INSERT INTO grants (user_id, kind, payload, ts) SELECT ?, ?, ?, ?' + cond).bind(u.id, 'gift', gp, now, row.id, row.price),
    env.DB.prepare('INSERT INTO grants (user_id, kind, payload, ts) SELECT ?, ?, ?, ?' + cond).bind(row.user_id, 'sale', sp, now, row.id, row.price),
    env.DB.prepare('DELETE FROM listings WHERE id = ? AND price = ?').bind(row.id, row.price)
  ]);
  if (!(res[2].meta && res[2].meta.changes > 0)) return err('Лот уже продан или снят', 409);

  try {
    if (sg.d.notif !== false) {
      const t = await env.DB.prepare('SELECT tg_id FROM tglink WHERE user_id = ?').bind(row.user_id).first();
      if (t) await tgSend(env, t.tg_id, 'Твой ' + row.col + ' #' + row.serial + ' купил @' + u.username + ' за ' + f2(row.price) + ' GRAM');
    }
  } catch (e) {}
  return json({ ok: true, grants: await pendingGrants(env, u.id) });
}

async function marketList_(env) {
  const { results } = await env.DB.prepare(
    'SELECT l.id, u.username AS seller, l.col, l.serial, l.price, l.vcap, l.vmul, l.ts FROM listings l JOIN users u ON u.id = l.user_id ' +
    'WHERE NOT EXISTS (SELECT 1 FROM bans b WHERE b.user_id = l.user_id) ORDER BY l.ts DESC LIMIT 600'
  ).all();
  return json({ items: results || [] });
}

async function route(req, env, url) {
  const path = url.pathname.replace(/\/+$/, ''), m = req.method;

  if (path === '/api/register' && m === 'POST') return register(req, env);
  if (path === '/api/login' && m === 'POST') return login(req, env);

  if (path === '/api/config' && m === 'GET') return json({ bot: appLink(env, ''), notify: !!env.BOT_TOKEN });
  if (path === '/api/tglink' && m === 'POST') {
    const a = await authed(req, env); if (a.res) return a.res;
    return tglink(req, env, a.u);
  }
  if (path === '/api/me' && m === 'GET') {
    const a = await authed(req, env); if (a.res) return a.res;
    return json({ username: a.u.username });
  }
  if (path === '/api/logout' && m === 'POST') {
    const t = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.get('authorization') || '');
    if (t) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(await sha(t[1])).run();
    return json({ ok: true });
  }
  if (path === '/api/load' && m === 'GET') {
    const a = await authed(req, env); if (a.res) return a.res;
    const u = a.u;
    const r = await env.DB.prepare('SELECT data, updated FROM saves WHERE user_id = ?').bind(u.id).first();
    return json({ username: u.username, data: r ? parse(r.data) : null, updated: r ? r.updated : 0, grants: await pendingGrants(env, u.id) });
  }
  if (path === '/api/grants' && m === 'GET') {
    const a = await authed(req, env); if (a.res) return a.res;
    return json({ grants: await pendingGrants(env, a.u.id) });
  }
  if (path === '/api/save' && m === 'PUT') {
    const a = await authed(req, env); if (a.res) return a.res;
    return save(req, env, a.u);
  }
  if (path === '/api/market' && m === 'GET') return marketList_(env);
  if (path === '/api/market/list' && m === 'POST') {
    const a = await authed(req, env); if (a.res) return a.res;
    return marketList(req, env, a.u);
  }
  if ((path === '/api/market/unlist' || path === '/api/market/claim') && m === 'POST') {
    const a = await authed(req, env); if (a.res) return a.res;
    return marketTake(req, env, a.u);
  }
  if (path === '/api/market/buy' && m === 'POST') {
    const a = await authed(req, env); if (a.res) return a.res;
    return marketBuy(req, env, a.u);
  }
  if (path === '/api/transfer' && m === 'POST') {
    const a = await authed(req, env); if (a.res) return a.res;
    return transfer(req, env, a.u);
  }
  if (path.startsWith('/api/admin/')) {
    const a = await authed(req, env); if (a.res) return a.res;
    return adminRoute(req, env, url, path, m, a.u);
  }

  if (path.startsWith('/api/user/') && m === 'GET') {
    const name = decodeURIComponent(path.slice(10));
    if (!USER_RE.test(name)) return err('Игрок не найден', 404);
    const r = await env.DB.prepare(
      'SELECT u.username, u.created, s.profile, s.updated FROM users u LEFT JOIN saves s ON s.user_id = u.id WHERE u.username = ?'
    ).bind(name).first();
    if (!r) return err('Игрок не найден', 404);
    const p = parse(r.profile) || { name: r.username, bio: '', col: 0, worn: null, gifts: [], count: 0, stats: { profit: 0, flips: 0, best: 0, vol: 0, spent: 0 }, worth: 0 };
    return json(Object.assign({ username: r.username, joined: r.created, seen: r.updated || 0 }, p));
  }
  if (path === '/api/search' && m === 'GET') {
    const q = (url.searchParams.get('q') || '').replace(/^@/, '');
    if (!/^[A-Za-z0-9_]{1,20}$/.test(q)) return json({ users: [] });
    const like = '%' + q.replace(/[\\%_]/g, '\\$&') + '%';
    const { results } = await env.DB.prepare(
      "SELECT u.username, s.profile FROM users u LEFT JOIN saves s ON s.user_id = u.id " +
      "WHERE u.username LIKE ? ESCAPE '\\' ORDER BY (lower(u.username) = lower(?)) DESC, length(u.username) ASC LIMIT 15"
    ).bind(like, q).all();
    return json({
      users: results.map(r => { const p = parse(r.profile) || {}; return { username: r.username, name: p.name || r.username, count: p.count || 0 }; })
    });
  }
  if (path === '/api/top' && m === 'GET') {
    const { results } = await env.DB.prepare(
      'SELECT u.username, s.profile FROM saves s JOIN users u ON u.id = s.user_id ' +
      'WHERE NOT EXISTS (SELECT 1 FROM bans b WHERE b.user_id = u.id) ORDER BY s.updated DESC LIMIT 150'
    ).all();
    const list = results.map(r => {
      const p = parse(r.profile) || {};
      const st = p.stats || {};
      return { username: r.username, name: p.name || r.username, profit: st.profit || 0, flips: st.flips || 0, worth: p.worth || 0, count: p.count || 0, ev: p.ev || 0 };
    });
    const byEv = list.filter(x => x.ev > 0).sort((a, b) => b.ev - a.ev).slice(0, 20);
    const top = list.sort((a, b) => b.profit - a.profit).slice(0, 20);
    for (const x of byEv) if (!top.includes(x)) top.push(x);
    return json({ users: top });
  }
  return err('Не найдено', 404);
}

const IMG_RE = /^\/img\/([a-z0-9]{3,30})-(\d{1,7})(\.l)?\.(jpg|json)$/;
async function upstream(path) {
  try {
    const r = await fetch('https://nft.fragment.com/gift/' + path, {
      headers: { 'user-agent': 'Mozilla/5.0' },
      cf: { cacheEverything: true, cacheTtl: 2592000 }
    });
    return r.ok ? r : null;
  } catch (e) { return null; }
}
async function imgProxy(req, url, ctx) {
  const m = IMG_RE.exec(url.pathname);
  const n = m ? Number(m[2]) : 0;
  if (!m || n < 1 || n > 1000000) return new Response('Not found', { status: 404 });
  const cache = typeof caches !== 'undefined' ? caches.default : null;
  const key = new Request(url.origin + url.pathname);
  if (cache) { try { const hit = await cache.match(key); if (hit) return hit; } catch (e) {} }
  const jpg = m[4] === 'jpg', base = m[1] + '-' + n;
  let r = null;
  if (!jpg) r = await upstream(base + '.json');
  else if (m[3]) r = (await upstream(base + '.large.jpg')) || (await upstream(base + '.medium.jpg'));
  else r = await upstream(base + '.medium.jpg');
  if (!r) return new Response('Not found', { status: 404, headers: { 'cache-control': 'public, max-age=300' } });
  const res = new Response(await r.arrayBuffer(), {
    status: 200,
    headers: {
      'content-type': jpg ? 'image/jpeg' : 'application/json; charset=utf-8',
      'cache-control': 'public, max-age=2592000, immutable',
      'access-control-allow-origin': '*',
      'x-content-type-options': 'nosniff'
    }
  });
  if (cache && ctx) ctx.waitUntil(cache.put(key, res.clone()).catch(() => {}));
  return res;
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/img/') && req.method === 'GET') return imgProxy(req, url, ctx);
    if (!url.pathname.startsWith('/api/' ) && url.pathname !== '/api') {
      return env.ASSETS ? env.ASSETS.fetch(req) : new Response('Not found', { status: 404 });
    }
    if (!env.DB) return err('База данных не подключена к серверу', 500);
    try {
      await init(env.DB);
      return await route(req, env, url);
    } catch (e) {
      return err('Ошибка сервера', 500);
    }
  },
  async scheduled(event, env, ctx) {
    if (env.DB) ctx.waitUntil(cron(env).catch(() => {}));
  }
};
