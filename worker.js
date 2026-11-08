/* Portals Market — сервер аккаунтов (Cloudflare Worker + D1)
   Маршруты /api/*; всё остальное отдаёт статика из папки public. */

const enc = new TextEncoder();
const ITER = 60000;                 /* итерации PBKDF2 (максимум в Workers — 100000). Хеш хранит своё число итераций */
const SESSION_MS = 30 * 864e5;      /* токен живёт 30 дней */

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
  ready = true;
}

/* ограничение частоты: не больше max попыток за окно windowMs */
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
    'SELECT u.id, u.username, s.created FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?'
  ).bind(await sha(m[1])).first();
  if (!row || Date.now() - row.created > SESSION_MS) return null;
  return row;
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
  return json({ token: await newSession(env, u.id), username: u.username });
}

/* публичная карточка игрока строится на сервере из сохранения — клиенту не доверяем */
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
    worth: num(worth, 0, 1e9)
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

  /* лёгкая защита от накрутки: прирост баланса/прибыли ограничен прошедшим временем */
  let pd = null;
  if (prev) { try { pd = JSON.parse(prev.data); } catch (e) {} }
  if (pd && Number.isFinite(pd.ton)) {
    const dt = Math.max(0, (now - prev.updated) / 1000), allow = Math.min(8000 + dt * 5, 100000);
    if (d.ton - pd.ton > allow || num(d.profit, -1e9, 1e9) - num(pd.profit, -1e9, 1e9) > allow ||
        num(d.vol, 0, 1e12) - num(pd.vol, 0, 1e12) > allow * 3 || num(d.flips, 0, 1e9) - num(pd.flips, 0, 1e9) > 40 + dt)
      return err('Сервер отклонил сохранение: слишком резкий рост баланса', 409);
  } else if (d.ton > 20000 || num(d.profit, -1e9, 1e9) > 20000) {
    return err('Сервер отклонил сохранение: слишком большой стартовый баланс', 409);
  }

  const profile = JSON.stringify(buildProfile(d, b.worth));
  await env.DB.prepare(
    'INSERT INTO saves (user_id, data, profile, updated) VALUES (?, ?, ?, ?) ' +
    'ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, profile = excluded.profile, updated = excluded.updated'
  ).bind(user.id, JSON.stringify(d), profile, now).run();
  return json({ ok: true, t: now });
}

const parse = s => { try { return JSON.parse(s); } catch (e) { return null; } };

async function route(req, env, url) {
  const path = url.pathname.replace(/\/+$/, ''), m = req.method;

  if (path === '/api/register' && m === 'POST') return register(req, env);
  if (path === '/api/login' && m === 'POST') return login(req, env);

  if (path === '/api/me' && m === 'GET') {
    const u = await auth(req, env);
    return u ? json({ username: u.username }) : err('Нужно войти', 401);
  }
  if (path === '/api/logout' && m === 'POST') {
    const t = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.get('authorization') || '');
    if (t) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(await sha(t[1])).run();
    return json({ ok: true });
  }
  if (path === '/api/load' && m === 'GET') {
    const u = await auth(req, env); if (!u) return err('Нужно войти', 401);
    const r = await env.DB.prepare('SELECT data, updated FROM saves WHERE user_id = ?').bind(u.id).first();
    return json({ username: u.username, data: r ? parse(r.data) : null, updated: r ? r.updated : 0 });
  }
  if (path === '/api/save' && m === 'PUT') {
    const u = await auth(req, env); if (!u) return err('Нужно войти', 401);
    return save(req, env, u);
  }

  /* публичные: профиль, поиск, топ */
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
      'SELECT u.username, s.profile FROM saves s JOIN users u ON u.id = s.user_id ORDER BY s.updated DESC LIMIT 150'
    ).all();
    const list = results.map(r => {
      const p = parse(r.profile) || {};
      const st = p.stats || {};
      return { username: r.username, name: p.name || r.username, profit: st.profit || 0, flips: st.flips || 0, worth: p.worth || 0, count: p.count || 0 };
    }).sort((a, b) => b.profit - a.profit).slice(0, 20);
    return json({ users: list });
  }
  return err('Не найдено', 404);
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
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
  }
};
