// Pick'em pool API — Cloudflare Worker + D1
// No build step, no dependencies — deploy straight with `wrangler deploy`.

// Only these sites are allowed to call the API from a browser
const ALLOWED_ORIGINS = ['https://tossup.me', 'https://www.tossup.me'];

const CORS_HEADERS = {
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

// ---------- crypto helpers ----------

const PBKDF2_ITERATIONS = 100000;

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

async function hashPassword(password, saltHex) {
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(salt) };
}

async function verifyPassword(password, hash, salt) {
  const result = await hashPassword(password, salt);
  return result.hash === hash;
}

function base64url(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

async function hmacSign(data, secret) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return base64url(String.fromCharCode(...new Uint8Array(sig)));
}

async function signSession(payload, secret) {
  const body = base64url(JSON.stringify(payload));
  const sig = await hmacSign(body, secret);
  return `${body}.${sig}`;
}

async function verifySession(token, secret) {
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expected = await hmacSign(body, secret);
  if (sig !== expected) return null;
  const payload = JSON.parse(base64urlDecode(body));
  if (payload.exp && Date.now() > payload.exp) return null;
  return payload;
}

async function getAuthedUserId(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace('Bearer ', '');
  if (!token) return null;
  const payload = await verifySession(token, env.JWT_SECRET);
  return payload ? payload.uid : null;
}

function generateInviteCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no ambiguous chars
  let code = '';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

async function getMembership(env, uid, groupId) {
  return env.DB.prepare('SELECT role FROM memberships WHERE user_id = ? AND group_id = ?').bind(uid, groupId).first();
}

// ---------- rate limiting ----------
// Generic "has this identifier done too much recently" check, backed by D1.
// identifier examples: `login:someone@email.com`, `signup:203.0.113.4`

async function tooManyRecentEvents(env, identifier, maxEvents, windowMinutes) {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) as count FROM rate_limit_events WHERE identifier = ? AND created_at > datetime('now', ?)`
  ).bind(identifier, `-${windowMinutes} minutes`).first();
  return row.count >= maxEvents;
}

async function recordEvent(env, identifier) {
  await env.DB.prepare('INSERT INTO rate_limit_events (identifier) VALUES (?)').bind(identifier).run();
}

async function clearEvents(env, identifier) {
  await env.DB.prepare('DELETE FROM rate_limit_events WHERE identifier = ?').bind(identifier).run();
}

// ---------- auth ----------

async function handleSignup(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await tooManyRecentEvents(env, `signup:${ip}`, 5, 60)) {
    return json({ error: 'Too many accounts created from this connection. Try again later.' }, 429);
  }

  const { name, email, password } = await request.json();
  if (!name || !email || !password) return json({ error: 'Name, email, and password are required' }, 400);
  if (password.length < 8) return json({ error: 'Password must be at least 8 characters' }, 400);

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  if (existing) return json({ error: 'An account with that email already exists' }, 409);

  const { hash, salt } = await hashPassword(password);
  const result = await env.DB.prepare(
    'INSERT INTO users (name, email, password_hash, password_salt) VALUES (?, ?, ?, ?)'
  ).bind(name, email.toLowerCase(), hash, salt).run();

  await recordEvent(env, `signup:${ip}`);

  const userId = result.meta.last_row_id;
  const token = await signSession({ uid: userId, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 }, env.JWT_SECRET);
  return json({ token, user: { id: userId, name, email } }, 201);
}

async function handleLogin(request, env) {
  const { email, password } = await request.json();
  const identifier = `login:${(email || '').toLowerCase()}`;

  if (await tooManyRecentEvents(env, identifier, 5, 15)) {
    return json({ error: 'Too many failed attempts. Try again in a few minutes.' }, 429);
  }

  const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind((email || '').toLowerCase()).first();
  const valid = user ? await verifyPassword(password, user.password_hash, user.password_salt) : false;

  if (!valid) {
    await recordEvent(env, identifier);
    return json({ error: 'Incorrect email or password' }, 401);
  }

  await clearEvents(env, identifier);
  const token = await signSession({ uid: user.id, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 }, env.JWT_SECRET);
  return json({ token, user: { id: user.id, name: user.name, email: user.email } });
}

async function handleGetMe(request, env) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const user = await env.DB.prepare(
    'SELECT id, name, email, venmo_handle, pick_mode, ad_free_until FROM users WHERE id = ?'
  ).bind(uid).first();
  return json({ user });
}

async function handleUpdateMe(request, env) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const { name, venmo_handle, pick_mode } = await request.json();
  if (pick_mode && !['global', 'per_group'].includes(pick_mode)) {
    return json({ error: 'pick_mode must be "global" or "per_group"' }, 400);
  }
  await env.DB.prepare(
    'UPDATE users SET name = COALESCE(?, name), venmo_handle = COALESCE(?, venmo_handle), pick_mode = COALESCE(?, pick_mode) WHERE id = ?'
  ).bind(name ?? null, venmo_handle ?? null, pick_mode ?? null, uid).run();
  return json({ ok: true });
}

// ---------- groups ----------

async function handleCreateGroup(request, env) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const { name, pool_enabled, pool_amount_per_person } = await request.json();
  if (!name) return json({ error: 'Group name is required' }, 400);

  let inviteCode, exists;
  do {
    inviteCode = generateInviteCode();
    exists = await env.DB.prepare('SELECT id FROM groups WHERE invite_code = ?').bind(inviteCode).first();
  } while (exists);

  const result = await env.DB.prepare(
    'INSERT INTO groups (name, invite_code, commissioner_id, pool_enabled, pool_amount_per_person) VALUES (?, ?, ?, ?, ?)'
  ).bind(name, inviteCode, uid, pool_enabled ? 1 : 0, pool_amount_per_person || null).run();

  const groupId = result.meta.last_row_id;
  await env.DB.prepare(
    'INSERT INTO memberships (user_id, group_id, role) VALUES (?, ?, ?)'
  ).bind(uid, groupId, 'commissioner').run();

  return json({ group: { id: groupId, name, invite_code: inviteCode } }, 201);
}

async function handleJoinGroup(request, env) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const { invite_code } = await request.json();
  const group = await env.DB.prepare('SELECT id, name FROM groups WHERE invite_code = ?')
    .bind((invite_code || '').toUpperCase()).first();
  if (!group) return json({ error: 'Invalid invite code' }, 404);

  const existing = await env.DB.prepare('SELECT 1 FROM memberships WHERE user_id = ? AND group_id = ?')
    .bind(uid, group.id).first();
  if (existing) return json({ error: 'Already a member of this group' }, 409);

  await env.DB.prepare('INSERT INTO memberships (user_id, group_id, role) VALUES (?, ?, ?)')
    .bind(uid, group.id, 'member').run();
  return json({ group });
}

async function handleListGroups(request, env) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const { results } = await env.DB.prepare(
    `SELECT g.id, g.name, g.invite_code, g.pool_enabled, g.pool_amount_per_person, m.role
     FROM groups g JOIN memberships m ON m.group_id = g.id
     WHERE m.user_id = ?`
  ).bind(uid).all();
  return json({ groups: results });
}

async function handleGetGroup(request, env, groupId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const membership = await getMembership(env, uid, groupId);
  if (!membership) return json({ error: 'Not a member of this group' }, 403);
  const group = await env.DB.prepare('SELECT * FROM groups WHERE id = ?').bind(groupId).first();
  return json({ group, role: membership.role });
}

async function handleUpdateGroup(request, env, groupId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const membership = await getMembership(env, uid, groupId);
  if (!membership || membership.role !== 'commissioner') {
    return json({ error: 'Only the commissioner can edit this group' }, 403);
  }
  const { name, pool_enabled, pool_amount_per_person } = await request.json();
  await env.DB.prepare(
    `UPDATE groups SET
       name = COALESCE(?, name),
       pool_enabled = COALESCE(?, pool_enabled),
       pool_amount_per_person = COALESCE(?, pool_amount_per_person)
     WHERE id = ?`
  ).bind(name ?? null, pool_enabled === undefined ? null : (pool_enabled ? 1 : 0), pool_amount_per_person ?? null, groupId).run();
  return json({ ok: true });
}

// ---------- games ----------

async function handleGetGames(request, env, seasonYear, weekNumber) {
  const week = await env.DB.prepare('SELECT id FROM weeks WHERE season_year = ? AND week_number = ?')
    .bind(seasonYear, weekNumber).first();
  if (!week) return json({ games: [] });
  const { results } = await env.DB.prepare('SELECT * FROM games WHERE week_id = ? ORDER BY kickoff_time')
    .bind(week.id).all();
  return json({ games: results });
}

// ---------- picks ----------

async function handleGetPicks(request, env, groupId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const membership = await getMembership(env, uid, groupId);
  if (!membership) return json({ error: 'Not a member of this group' }, 403);

  const url = new URL(request.url);
  const seasonYear = url.searchParams.get('season');
  const weekNumber = url.searchParams.get('week');
  const week = await env.DB.prepare('SELECT id FROM weeks WHERE season_year = ? AND week_number = ?')
    .bind(seasonYear, weekNumber).first();
  if (!week) return json({ games: [] });

  const user = await env.DB.prepare('SELECT pick_mode FROM users WHERE id = ?').bind(uid).first();
  const { results: games } = await env.DB.prepare('SELECT * FROM games WHERE week_id = ? ORDER BY kickoff_time')
    .bind(week.id).all();

  const groupIdFilter = user.pick_mode === 'per_group' ? groupId : null;
  const { results: picks } = await env.DB.prepare(
    `SELECT game_id, picked_team FROM picks
     WHERE user_id = ? AND game_id IN (SELECT id FROM games WHERE week_id = ?) AND group_id IS ?`
  ).bind(uid, week.id, groupIdFilter).all();

  const pickMap = Object.fromEntries(picks.map((p) => [p.game_id, p.picked_team]));
  const now = Date.now();
  const gamesWithPicks = games.map((g) => ({
    ...g,
    picked_team: pickMap[g.id] || null,
    locked: new Date(g.kickoff_time).getTime() <= now,
  }));

  return json({ pick_mode: user.pick_mode, games: gamesWithPicks });
}

async function handleSubmitPick(request, env) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const { game_id, group_id, picked_team } = await request.json();
  if (!game_id || !picked_team) return json({ error: 'game_id and picked_team are required' }, 400);

  const game = await env.DB.prepare('SELECT kickoff_time FROM games WHERE id = ?').bind(game_id).first();
  if (!game) return json({ error: 'Game not found' }, 404);
  if (new Date(game.kickoff_time).getTime() <= Date.now()) {
    return json({ error: 'This game has already kicked off — the pick is locked' }, 409);
  }

  const user = await env.DB.prepare('SELECT pick_mode FROM users WHERE id = ?').bind(uid).first();
  const effectiveGroupId = user.pick_mode === 'per_group' ? group_id : null;

  if (effectiveGroupId) {
    const membership = await getMembership(env, uid, effectiveGroupId);
    if (!membership) return json({ error: 'Not a member of this group' }, 403);
  }

  const existing = await env.DB.prepare(
    'SELECT id FROM picks WHERE user_id = ? AND game_id = ? AND group_id IS ?'
  ).bind(uid, game_id, effectiveGroupId).first();

  if (existing) {
    await env.DB.prepare('UPDATE picks SET picked_team = ?, updated_at = datetime("now") WHERE id = ?')
      .bind(picked_team, existing.id).run();
  } else {
    await env.DB.prepare('INSERT INTO picks (user_id, game_id, group_id, picked_team) VALUES (?, ?, ?, ?)')
      .bind(uid, game_id, effectiveGroupId, picked_team).run();
  }

  return json({ ok: true });
}

// ---------- standings ----------

async function handleStandings(request, env, groupId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const membership = await getMembership(env, uid, groupId);
  if (!membership) return json({ error: 'Not a member of this group' }, 403);

  const url = new URL(request.url);
  const type = url.searchParams.get('type') === 'season' ? 'season' : 'weekly';
  const seasonYear = url.searchParams.get('season');
  const weekNumber = url.searchParams.get('week') || 0;
  const isSeasonMode = type === 'season' ? 1 : 0;

  const { results } = await env.DB.prepare(
    `SELECT u.id, u.name,
        SUM(CASE WHEN g.final_winner IS NOT NULL AND p.picked_team = g.final_winner THEN 1 ELSE 0 END) AS points,
        SUM(CASE WHEN g.final_winner IS NOT NULL THEN 1 ELSE 0 END) AS games_final
     FROM memberships m
     JOIN users u ON u.id = m.user_id
     JOIN weeks w ON w.season_year = ?
     JOIN games g ON g.week_id = w.id AND (? = 1 OR w.week_number = ?)
     LEFT JOIN picks p ON p.user_id = u.id AND p.game_id = g.id
        AND p.group_id IS (CASE WHEN u.pick_mode = 'per_group' THEN ? ELSE NULL END)
     WHERE m.group_id = ?
     GROUP BY u.id, u.name
     ORDER BY points DESC`
  ).bind(seasonYear, isSeasonMode, weekNumber, groupId, groupId).all();

  return json({ type, standings: results });
}

// ---------- pool ----------

async function handlePool(request, env, groupId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const membership = await getMembership(env, uid, groupId);
  if (!membership) return json({ error: 'Not a member of this group' }, 403);

  const group = await env.DB.prepare('SELECT pool_enabled, pool_amount_per_person FROM groups WHERE id = ?')
    .bind(groupId).first();
  if (!group.pool_enabled) return json({ pool_enabled: false });

  const url = new URL(request.url);
  const seasonYear = url.searchParams.get('season');
  const weekNumber = url.searchParams.get('week');
  let week = await env.DB.prepare('SELECT id FROM weeks WHERE season_year = ? AND week_number = ?')
    .bind(seasonYear, weekNumber).first();
  if (!week) {
    const result = await env.DB.prepare('INSERT INTO weeks (season_year, week_number) VALUES (?, ?)')
      .bind(seasonYear, weekNumber).run();
    week = { id: result.meta.last_row_id };
  }

  const { results: members } = await env.DB.prepare(
    'SELECT u.id, u.name FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.group_id = ?'
  ).bind(groupId).all();

  for (const member of members) {
    await env.DB.prepare(
      `INSERT INTO pool_payments (group_id, week_id, user_id, amount_owed)
       VALUES (?, ?, ?, ?)
       ON CONFLICT (group_id, week_id, user_id) DO NOTHING`
    ).bind(groupId, week.id, member.id, group.pool_amount_per_person).run();
  }

  const { results: payments } = await env.DB.prepare(
    `SELECT u.id, u.name, pp.paid, pp.amount_owed
     FROM pool_payments pp JOIN users u ON u.id = pp.user_id
     WHERE pp.group_id = ? AND pp.week_id = ?`
  ).bind(groupId, week.id).all();

  const total = payments.reduce((sum, p) => sum + p.amount_owed, 0);
  return json({ pool_enabled: true, total, members: payments });
}

async function handleMarkPaid(request, env, groupId, userId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const membership = await getMembership(env, uid, groupId);
  if (!membership || membership.role !== 'commissioner') {
    return json({ error: 'Only the commissioner can confirm payments' }, 403);
  }

  const url = new URL(request.url);
  const seasonYear = url.searchParams.get('season');
  const weekNumber = url.searchParams.get('week');
  const week = await env.DB.prepare('SELECT id FROM weeks WHERE season_year = ? AND week_number = ?')
    .bind(seasonYear, weekNumber).first();
  if (!week) return json({ error: 'Week not found' }, 404);

  await env.DB.prepare(
    'UPDATE pool_payments SET paid = 1, confirmed_at = datetime("now") WHERE group_id = ? AND week_id = ? AND user_id = ?'
  ).bind(groupId, week.id, userId).run();

  return json({ ok: true });
}

// ---------- router ----------

async function route(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;

      if (path === '/api/signup' && method === 'POST') return handleSignup(request, env);
      if (path === '/api/login' && method === 'POST') return handleLogin(request, env);
      if (path === '/api/me' && method === 'GET') return handleGetMe(request, env);
      if (path === '/api/me' && method === 'PATCH') return handleUpdateMe(request, env);

      if (path === '/api/groups' && method === 'POST') return handleCreateGroup(request, env);
      if (path === '/api/groups' && method === 'GET') return handleListGroups(request, env);
      if (path === '/api/groups/join' && method === 'POST') return handleJoinGroup(request, env);

      const groupMatch = path.match(/^\/api\/groups\/(\d+)$/);
      if (groupMatch && method === 'GET') return handleGetGroup(request, env, groupMatch[1]);
      if (groupMatch && method === 'PATCH') return handleUpdateGroup(request, env, groupMatch[1]);

      const picksMatch = path.match(/^\/api\/groups\/(\d+)\/picks$/);
      if (picksMatch && method === 'GET') return handleGetPicks(request, env, picksMatch[1]);
      if (path === '/api/picks' && method === 'POST') return handleSubmitPick(request, env);

      const standingsMatch = path.match(/^\/api\/groups\/(\d+)\/standings$/);
      if (standingsMatch && method === 'GET') return handleStandings(request, env, standingsMatch[1]);

      const poolMatch = path.match(/^\/api\/groups\/(\d+)\/pool$/);
      if (poolMatch && method === 'GET') return handlePool(request, env, poolMatch[1]);

      const markPaidMatch = path.match(/^\/api\/groups\/(\d+)\/pool\/(\d+)\/mark-paid$/);
      if (markPaidMatch && method === 'POST') {
        return handleMarkPaid(request, env, markPaidMatch[1], markPaidMatch[2]);
      }

      const gamesMatch = path.match(/^\/api\/weeks\/(\d+)\/(\d+)\/games$/);
      if (gamesMatch && method === 'GET') return handleGetGames(request, env, gamesMatch[1], gamesMatch[2]);

      return json({ error: 'Not found' }, 404);
    } catch (err) {
      return json({ error: 'Server error', detail: String(err) }, 500);
    }
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const allowOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: { ...CORS_HEADERS, 'Access-Control-Allow-Origin': allowOrigin } });
    }

    const response = await route(request, env);
    response.headers.set('Access-Control-Allow-Origin', allowOrigin);
    return response;
  },
};
