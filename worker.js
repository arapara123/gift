/* Portals Market — сервер аккаунтов (Cloudflare Worker + D1)
   Маршруты /api/*; всё остальное отдаёт статика из папки public. */

const enc = new TextEncoder();
const ITER = 60000;                 /* итерации PBKDF2 (максимум в Workers — 100000). Хеш хранит своё число итераций */
const SESSION_MS = 30 * 864e5;      /* токен живёт 30 дней */
const ADMIN = 'admin';              /* единственный аккаунт-администратор (регистр важен) */
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
  await db.exec('CREATE TABLE IF NOT EXISTS trades (id INTEGER PRIMARY KEY AUTOINCREMENT, from_id INTEGER NOT NULL, to_id INTEGER NOT NULL, col TEXT NOT NULL, serial INTEGER NOT NULL, price REAL NOT NULL, vcap REAL NOT NULL DEFAULT 0, vmul REAL NOT NULL DEFAULT 0, ts INTEGER NOT NULL, status TEXT NOT NULL DEFAULT \'pending\')');
  await db.exec('CREATE INDEX IF NOT EXISTS trades_to ON trades (to_id, status)');
  await db.exec('CREATE INDEX IF NOT EXISTS trades_from ON trades (from_id, status)');
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
    'SELECT u.id, u.username, s.created, b.reason AS ban_reason, (b.user_id IS NOT NULL) AS banned ' +
    'FROM sessions s JOIN users u ON u.id = s.user_id LEFT JOIN bans b ON b.user_id = u.id WHERE s.token = ?'
  ).bind(await sha(m[1])).first();
  if (!row || Date.now() - row.created > SESSION_MS) return null;
  return row;
}
const banMsg = r => 'Аккаунт заблокирован' + (r && r.length ? ': ' + r : '');

/* вошедший и не заблокированный пользователь, либо готовый ответ с ошибкой */
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

  /* выдачи администратора, которые клиент подтверждает как применённые:
     берём только реальные, ещё не применённые выдачи этого же игрока */
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

  /* лёгкая защита от накрутки: прирост баланса/прибыли ограничен прошедшим временем.
     Выданные админом TON добавляются к допустимому приросту баланса (но не прибыли и не оборота) */
  /* ЗАЩИТА ОТ НАКРУТКИ ОТКЛЮЧЕНА: рост баланса, прибыли и оборота больше не ограничивается.
     Остались только базовые проверки выше (баланс от 0 до 1 000 000 TON). */

  /* если админ сбросил статистику, а клиент ещё не подтвердил это (не применил выдачу) —
     старые цифры из его сохранения не принимаем, иначе они вернутся обратно */
  {
    const rs = await env.DB.prepare("SELECT id FROM grants WHERE user_id = ? AND applied = 0 AND kind = 'reset-stats'").bind(user.id).all();
    if ((rs.results || []).some(r => !ack.includes(r.id))) { d.profit = 0; d.flips = 0; d.best = 0; d.vol = 0; d.spent = 0; }
  }

  /* подарок, который уже продан другому игроку, но продавец ещё не применил выдачу: из его сохранения убираем */
  {
    const ts = await env.DB.prepare("SELECT id, payload FROM grants WHERE user_id = ? AND applied = 0 AND kind = 'trade-sale'").bind(user.id).all();
    for (const r of (ts.results || [])) {
      if (ack.includes(r.id)) continue;
      const p = parse(r.payload) || {};
      const g = d.inv.find(x => x && !x.base && x.col === p.col && Number(x.serial) === p.serial);
      if (g) dropGift(d, g.id);
    }
  }

  const profile = JSON.stringify(buildProfile(d, b.worth));
  const stmts = [env.DB.prepare(
    'INSERT INTO saves (user_id, data, profile, updated) VALUES (?, ?, ?, ?) ' +
    'ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, profile = excluded.profile, updated = excluded.updated'
  ).bind(user.id, JSON.stringify(d), profile, now)];
  for (const r of gr) stmts.push(env.DB.prepare('UPDATE grants SET applied = 1 WHERE id = ? AND user_id = ?').bind(r.id, user.id));
  await env.DB.batch(stmts);
  return json({ ok: true, t: now });
}

/* передача подарка другому игроку: подарок должен реально лежать в сохранении отправителя;
   сервер сам убирает его оттуда и создаёт выдачу получателю (применяется при его следующем входе) */
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

function dropGift(d, gid) {
  d.inv = (d.inv || []).filter(g => !(g && g.id === gid));
  d.market = (d.market || []).filter(g => !(g && g.id === gid));
  d.pinned = (d.pinned || []).filter(x => x !== gid);
  d.offers = (d.offers || []).filter(o => !(o && o.gid === gid));
  if (d.worn === gid) d.worn = null;
}

const parse = s => { try { return JSON.parse(s); } catch (e) { return null; } };

async function pendingGrants(env, userId) {
  const { results } = await env.DB.prepare(
    'SELECT id, kind, payload FROM grants WHERE user_id = ? AND applied = 0 ORDER BY id LIMIT 50'
  ).bind(userId).all();
  return results.map(r => Object.assign({ id: r.id, kind: r.kind }, parse(r.payload) || {}));
}

/* ================= АДМИНИСТРАТОР ================= */
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
          count: p.count || 0, seen: r.updated || 0, banned: !!r.banned, reason: r.ban_reason || ''
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
    /* обнуляем статистику сразу в сохранении и профиле, а игроку отправляем команду,
       чтобы его устройство тоже обнулилось и не перезаписало сервер старыми цифрами */
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
    if (!Number.isFinite(amount) || amount === 0 || Math.abs(amount) > 500000) return err('Сумма: от 0.01 до 500000 TON (можно со знаком минус)');
    await env.DB.prepare('INSERT INTO grants (user_id, kind, payload, ts) VALUES (?, ?, ?, ?)')
      .bind(t.id, 'ton', JSON.stringify({ amount }), Date.now()).run();
    await adminLog(env, u.username, 'give-ton', t.username, amount);
    return json({ ok: true });
  }

  if (path === '/api/admin/give-gift') {
    const col = String(b.col || '');
    if (!COL_RE.test(col)) return err('Неверная коллекция');
    const serial = int(b.serial, 0, 1000000);   /* 0 — обычный (неулучшенный) подарок */
    await env.DB.prepare('INSERT INTO grants (user_id, kind, payload, ts) VALUES (?, ?, ?, ?)')
      .bind(t.id, 'gift', JSON.stringify({ col, serial }), Date.now()).run();
    await adminLog(env, u.username, 'give-gift', t.username, col + ' #' + serial);
    return json({ ok: true });
  }

  return err('Не найдено', 404);
}

/* ================= ПРОДАЖА ПОДАРКОВ ДРУГИМ ИГРОКАМ ================= */
const TRADE_MS = 864e5;   /* предложение живёт сутки */

async function tradeOffer(req, env, u) {
  let b; try { b = await readJson(req); } catch (e) { return err('Неверный запрос'); }
  const t = await findUser(env, b.user);
  if (!t) return err('Игрок не найден', 404);
  if (t.id === u.id) return err('Нельзя продать подарок самому себе');
  if (await env.DB.prepare('SELECT 1 AS x FROM bans WHERE user_id = ?').bind(t.id).first()) return err('Этот игрок заблокирован');
  const col = String(b.col || '');
  if (!COL_RE.test(col)) return err('Неверная коллекция');
  const serial = int(b.serial, 1, 1000000);
  const price = Math.round(Number(b.price) * 100) / 100;
  if (!Number.isFinite(price) || price < 0 || price > 500000) return err('Цена: от 0 до 500000 TON');
  if (await limited(env.DB, 'toffer:' + u.id, 30, 3600000)) return err('Слишком много предложений. Попробуйте позже', 429);
  const now = Date.now();
  const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM trades WHERE from_id = ? AND status = 'pending' AND ts > ?").bind(u.id, now - TRADE_MS).first();
  if (cnt && cnt.n >= 20) return err('Слишком много активных предложений (максимум 20). Отмените лишние');
  const row = await env.DB.prepare('SELECT data FROM saves WHERE user_id = ?').bind(u.id).first();
  const d = row && parse(row.data);
  const g = d && Array.isArray(d.inv) ? d.inv.find(x => x && !x.base && x.col === col && Number(x.serial) === serial) : null;
  if (!g) return err('Подарок не найден в сохранении. Подождите пару секунд и повторите');
  await env.DB.batch([
    env.DB.prepare("UPDATE trades SET status = 'cancelled' WHERE from_id = ? AND col = ? AND serial = ? AND status = 'pending'").bind(u.id, col, serial),
    env.DB.prepare('INSERT INTO trades (from_id, to_id, col, serial, price, vcap, vmul, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(u.id, t.id, col, serial, price, num(g.vcap, 0, 1e7), num(g.vmul, 0, 1000), now)
  ]);
  return json({ ok: true });
}

async function tradeList(env, u) {
  const since = Date.now() - TRADE_MS;
  const inc = await env.DB.prepare(
    "SELECT t.id, t.col, t.serial, t.price, t.ts, x.username AS other FROM trades t JOIN users x ON x.id = t.from_id " +
    "WHERE t.to_id = ? AND t.status = 'pending' AND t.ts > ? ORDER BY t.id DESC LIMIT 30"
  ).bind(u.id, since).all();
  const out = await env.DB.prepare(
    "SELECT t.id, t.col, t.serial, t.price, t.ts, x.username AS other FROM trades t JOIN users x ON x.id = t.to_id " +
    "WHERE t.from_id = ? AND t.status = 'pending' AND t.ts > ? ORDER BY t.id DESC LIMIT 30"
  ).bind(u.id, since).all();
  return json({ in: inc.results || [], out: out.results || [] });
}

async function tradeClose(req, env, u) {
  let b; try { b = await readJson(req); } catch (e) { return err('Неверный запрос'); }
  const id = int(b.id, 1, 1e12);
  const t = await env.DB.prepare("SELECT from_id, to_id FROM trades WHERE id = ? AND status = 'pending'").bind(id).first();
  if (!t || (t.from_id !== u.id && t.to_id !== u.id)) return err('Предложение не найдено', 404);
  await env.DB.prepare("UPDATE trades SET status = ? WHERE id = ? AND status = 'pending'").bind(t.from_id === u.id ? 'cancelled' : 'declined', id).run();
  return json({ ok: true });
}

/* покупка: сервер сам проверяет баланс покупателя и наличие подарка у продавца,
   убирает подарок из сохранения продавца и выдаёт грант покупателю (−TON, +подарок) и продавцу (+TON) */
async function tradeAccept(req, env, u) {
  let b; try { b = await readJson(req); } catch (e) { return err('Неверный запрос'); }
  const id = int(b.id, 1, 1e12), now = Date.now();
  const t = await env.DB.prepare("SELECT * FROM trades WHERE id = ? AND to_id = ? AND status = 'pending' AND ts > ?").bind(id, u.id, now - TRADE_MS).first();
  if (!t) return err('Предложение устарело или отменено', 404);
  const seller = await env.DB.prepare(
    'SELECT u.id, u.username, (b.user_id IS NOT NULL) AS banned FROM users u LEFT JOIN bans b ON b.user_id = u.id WHERE u.id = ?'
  ).bind(t.from_id).first();
  if (!seller || seller.banned) return err('Продавец недоступен');

  const brow = await env.DB.prepare('SELECT data FROM saves WHERE user_id = ?').bind(u.id).first();
  const bd = brow && parse(brow.data);
  if (!bd || !Number.isFinite(bd.ton)) return err('Не удалось проверить баланс. Повторите через пару секунд');
  const pend = await env.DB.prepare("SELECT payload FROM grants WHERE user_id = ? AND applied = 0 AND kind = 'trade-buy'").bind(u.id).all();
  let held = 0;
  for (const r of (pend.results || [])) held += Number((parse(r.payload) || {}).amount) || 0;
  if (bd.ton - held + 1e-9 < t.price) return err('Не хватает TON');

  const srow = await env.DB.prepare('SELECT data, profile FROM saves WHERE user_id = ?').bind(t.from_id).first();
  const sd = srow && parse(srow.data);
  const g = sd && Array.isArray(sd.inv) ? sd.inv.find(x => x && !x.base && x.col === t.col && Number(x.serial) === t.serial) : null;
  if (!g) {
    await env.DB.prepare("UPDATE trades SET status = 'cancelled' WHERE id = ? AND status = 'pending'").bind(id).run();
    return err('Подарок уже недоступен у продавца');
  }
  const claim = await env.DB.prepare("UPDATE trades SET status = 'accepted' WHERE id = ? AND status = 'pending'").bind(id).run();
  if (!claim.meta || !claim.meta.changes) return err('Предложение уже закрыто', 409);

  const vcap = num(g.vcap, 0, 1e7), vmul = num(g.vmul, 0, 1000);
  dropGift(sd, g.id);
  const worth = (parse(srow.profile) || {}).worth || 0;
  await env.DB.batch([
    env.DB.prepare('UPDATE saves SET data = ?, profile = ? WHERE user_id = ?').bind(JSON.stringify(sd), JSON.stringify(buildProfile(sd, worth)), t.from_id),
    env.DB.prepare("UPDATE trades SET status = 'cancelled' WHERE from_id = ? AND col = ? AND serial = ? AND status = 'pending'").bind(t.from_id, t.col, t.serial),
    env.DB.prepare('INSERT INTO grants (user_id, kind, payload, ts) VALUES (?, ?, ?, ?)')
      .bind(u.id, 'trade-buy', JSON.stringify({ col: t.col, serial: t.serial, amount: t.price, from: seller.username, vcap, vmul }), now),
    env.DB.prepare('INSERT INTO grants (user_id, kind, payload, ts) VALUES (?, ?, ?, ?)')
      .bind(t.from_id, 'trade-sale', JSON.stringify({ col: t.col, serial: t.serial, amount: t.price, to: u.username }), now)
  ]);
  await adminLog(env, u.username, 'trade', seller.username, t.col + ' #' + t.serial + ' for ' + t.price);
  return json({ ok: true });
}

async function route(req, env, url) {
  const path = url.pathname.replace(/\/+$/, ''), m = req.method;

  if (path === '/api/register' && m === 'POST') return register(req, env);
  if (path === '/api/login' && m === 'POST') return login(req, env);

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
  if (path === '/api/transfer' && m === 'POST') {
    const a = await authed(req, env); if (a.res) return a.res;
    return transfer(req, env, a.u);
  }
  if (path === '/api/trade/list' && m === 'GET') {
    const a = await authed(req, env); if (a.res) return a.res;
    return tradeList(env, a.u);
  }
  if (path === '/api/trade/offer' && m === 'POST') {
    const a = await authed(req, env); if (a.res) return a.res;
    return tradeOffer(req, env, a.u);
  }
  if (path === '/api/trade/accept' && m === 'POST') {
    const a = await authed(req, env); if (a.res) return a.res;
    return tradeAccept(req, env, a.u);
  }
  if (path === '/api/trade/close' && m === 'POST') {
    const a = await authed(req, env); if (a.res) return a.res;
    return tradeClose(req, env, a.u);
  }
  if (path.startsWith('/api/admin/')) {
    const a = await authed(req, env); if (a.res) return a.res;
    return adminRoute(req, env, url, path, m, a.u);
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
      'SELECT u.username, s.profile FROM saves s JOIN users u ON u.id = s.user_id ' +
      'WHERE NOT EXISTS (SELECT 1 FROM bans b WHERE b.user_id = u.id) ORDER BY s.updated DESC LIMIT 150'
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

/* Прокси картинок и данных подарков Fragment: браузер ходит на наш сайт, а не на nft.fragment.com
   (у части пользователей Fragment и обычные прокси заблокированы). Хост зашит в коде, поэтому открытым прокси это не является. */
const IMG_RE = /^\/img\/([a-z0-9]{3,30})-(\d{1,7})\.(jpg|json)$/;
async function imgProxy(url) {
  const m = IMG_RE.exec(url.pathname);
  const n = m ? Number(m[2]) : 0;
  if (!m || n < 1 || n > 1000000) return new Response('Not found', { status: 404 });
  const jpg = m[3] === 'jpg';
  let r;
  try {
    r = await fetch('https://nft.fragment.com/gift/' + m[1] + '-' + n + (jpg ? '.medium.jpg' : '.json'), {
      headers: { 'user-agent': 'Mozilla/5.0 (compatible; PortalsGame)' },
      cf: { cacheEverything: true, cacheTtl: 2592000 }
    });
  } catch (e) { return new Response('Bad gateway', { status: 502 }); }
  if (!r.ok) return new Response('Not found', { status: r.status === 404 ? 404 : 502 });
  return new Response(r.body, {
    status: 200,
    headers: {
      'content-type': jpg ? 'image/jpeg' : 'application/json; charset=utf-8',
      'cache-control': 'public, max-age=2592000',
      'access-control-allow-origin': '*',
      'x-content-type-options': 'nosniff'
    }
  });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/img/') && req.method === 'GET') return imgProxy(url);
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
