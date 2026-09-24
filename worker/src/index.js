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

// Trims and collapses whitespace in user-typed text (names, group names)
function cleanText(value) {
  return typeof value === 'string' ? value.replace(/\s+/g, ' ').trim() : '';
}

// "Parker Wall" -> "Parker W." — what strangers see on the community leaderboard
function publicName(name) {
  const parts = cleanText(name).split(' ').filter(Boolean);
  if (parts.length === 0) return 'Player';
  if (parts.length === 1) return parts[0];
  return `${parts[0]} ${parts[parts.length - 1][0].toUpperCase()}.`;
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

  const body = await request.json();
  const name = cleanText(body.name);
  const { email, password } = body;
  if (!name || !email || !password) return json({ error: 'Name, email, and password are required' }, 400);
  if (name.length > 40) return json({ error: 'Name must be 40 characters or fewer' }, 400);
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
  const body = await request.json();
  const sets = [];
  const params = [];

  if (body.name !== undefined) {
    const name = cleanText(body.name);
    if (!name || name.length > 40) return json({ error: 'Name must be 1–40 characters' }, 400);
    sets.push('name = ?');
    params.push(name);
  }
  if (body.venmo_handle !== undefined) {
    const handle = String(body.venmo_handle || '').trim().replace(/^@+/, '');
    if (handle && !/^[A-Za-z0-9_-]{2,30}$/.test(handle)) {
      return json({ error: 'Venmo usernames use letters, numbers, - and _ (up to 30)' }, 400);
    }
    sets.push('venmo_handle = ?');
    params.push(handle || null); // empty clears it
  }

  if (sets.length) {
    await env.DB.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).bind(...params, uid).run();
  }
  const user = await env.DB.prepare('SELECT id, name, email, venmo_handle FROM users WHERE id = ?').bind(uid).first();
  return json({ ok: true, user });
}

// ---------- groups ----------

// Accepts a bare code ("7F3K9Q"), a code with spaces, or a whole invite link
function normalizeInviteCode(value) {
  const text = String(value || '').toUpperCase();
  const fromLink = text.match(/JOIN=([A-Z0-9]+)/);
  return (fromLink ? fromLink[1] : text).replace(/[^A-Z0-9]/g, '').slice(0, 12);
}

// GET /api/invite/:code — what an invite link shows before you join. No login needed
// (the code itself is the secret), rate limited per connection to stop code guessing.
async function handleInvitePreview(request, env, rawCode) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await tooManyRecentEvents(env, `invite:${ip}`, 30, 10)) {
    return json({ error: 'Too many requests. Try again in a few minutes.' }, 429);
  }
  await recordEvent(env, `invite:${ip}`);

  const group = await env.DB.prepare(
    `SELECT g.id, g.name, g.pool_enabled, g.pool_amount_per_person, u.name AS commissioner_name,
            (SELECT COUNT(*) FROM memberships m WHERE m.group_id = g.id) AS member_count
     FROM groups g JOIN users u ON u.id = g.commissioner_id
     WHERE g.invite_code = ?`
  ).bind(normalizeInviteCode(rawCode)).first();
  if (!group) return json({ error: "This invite link isn't valid anymore. Ask for a new one." }, 404);

  const uid = await getAuthedUserId(request, env);
  const alreadyMember = uid ? !!(await getMembership(env, uid, group.id)) : false;
  return json({
    group: {
      name: group.name,
      member_count: group.member_count,
      commissioner: cleanText(group.commissioner_name).split(' ')[0] || 'The commissioner',
      pool_enabled: !!group.pool_enabled,
      pool_amount_per_person: group.pool_amount_per_person,
    },
    already_member: alreadyMember,
    group_id: alreadyMember ? group.id : null,
  });
}

async function handleCreateGroup(request, env) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const body = await request.json();
  const name = cleanText(body.name);
  const { pool_enabled, pool_amount_per_person } = body;
  if (!name) return json({ error: 'Group name is required' }, 400);
  if (name.length > 40) return json({ error: 'Group name must be 40 characters or fewer' }, 400);

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
  // Only wrong codes count toward the limit, so real joins are never blocked
  if (await tooManyRecentEvents(env, `join:${uid}`, 20, 10)) {
    return json({ error: 'Too many wrong codes. Try again in a few minutes.' }, 429);
  }

  const { invite_code } = await request.json();
  const code = normalizeInviteCode(invite_code);
  if (!code) return json({ error: 'Enter an invite code or link' }, 400);

  const group = await env.DB.prepare('SELECT id, name FROM groups WHERE invite_code = ?').bind(code).first();
  if (!group) {
    await recordEvent(env, `join:${uid}`);
    return json({ error: "That code doesn't match any league. Check it and try again." }, 404);
  }

  if (await getMembership(env, uid, group.id)) return json({ group, already_member: true });

  await env.DB.prepare('INSERT INTO memberships (user_id, group_id, role) VALUES (?, ?, ?)')
    .bind(uid, group.id, 'member').run();
  return json({ group, already_member: false });
}

async function handleListGroups(request, env) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const { results } = await env.DB.prepare(
    `SELECT g.id, g.name, g.invite_code, g.pool_enabled, g.pool_amount_per_person, m.role,
            (SELECT COUNT(*) FROM memberships m2 WHERE m2.group_id = g.id) AS member_count
     FROM groups g JOIN memberships m ON m.group_id = g.id
     WHERE m.user_id = ?
     ORDER BY g.name`
  ).bind(uid).all();
  return json({ groups: results });
}

async function handleGetGroup(request, env, groupId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const membership = await getMembership(env, uid, groupId);
  if (!membership) return json({ error: 'Not a member of this group' }, 403);
  const group = await env.DB.prepare('SELECT * FROM groups WHERE id = ?').bind(groupId).first();
  const { results: members } = await env.DB.prepare(
    `SELECT u.id, u.name, m.role FROM memberships m JOIN users u ON u.id = m.user_id
     WHERE m.group_id = ? ORDER BY (m.role = 'commissioner') DESC, u.name`
  ).bind(groupId).all();
  const commish = await env.DB.prepare('SELECT venmo_handle FROM users WHERE id = ?').bind(group.commissioner_id).first();
  return json({ group, role: membership.role, members, commissioner_venmo: commish ? commish.venmo_handle : null });
}

async function handleUpdateGroup(request, env, groupId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const membership = await getMembership(env, uid, groupId);
  if (!membership || membership.role !== 'commissioner') {
    return json({ error: 'Only the commissioner can edit this group' }, 403);
  }
  const body = await request.json();
  const name = body.name === undefined ? undefined : cleanText(body.name);
  const { pool_enabled, pool_amount_per_person } = body;
  if (name !== undefined && (!name || name.length > 40)) {
    return json({ error: 'Group name must be 1–40 characters' }, 400);
  }
  if (pool_amount_per_person !== undefined && pool_amount_per_person !== null
      && !(Number(pool_amount_per_person) > 0 && Number(pool_amount_per_person) <= 1000)) {
    return json({ error: 'Pool amount must be between $0 and $1,000' }, 400);
  }
  await env.DB.prepare(
    `UPDATE groups SET
       name = COALESCE(?, name),
       pool_enabled = COALESCE(?, pool_enabled),
       pool_amount_per_person = COALESCE(?, pool_amount_per_person)
     WHERE id = ?`
  ).bind(name ?? null, pool_enabled === undefined ? null : (pool_enabled ? 1 : 0), pool_amount_per_person ?? null, groupId).run();
  return json({ ok: true });
}

async function handleRemoveMember(request, env, groupId, targetUserId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const membership = await getMembership(env, uid, groupId);
  if (!membership || membership.role !== 'commissioner') {
    return json({ error: 'Only the commissioner can remove members' }, 403);
  }
  if (String(targetUserId) === String(uid)) {
    return json({ error: 'Delete the group instead of removing yourself' }, 400);
  }
  await env.DB.prepare('DELETE FROM memberships WHERE user_id = ? AND group_id = ?').bind(targetUserId, groupId).run();
  return json({ ok: true });
}

async function handleLeaveGroup(request, env, groupId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const membership = await getMembership(env, uid, groupId);
  if (!membership) return json({ error: 'Not a member of this group' }, 403);
  if (membership.role === 'commissioner') {
    return json({ error: 'As commissioner, delete the group instead of leaving it' }, 400);
  }
  await env.DB.prepare('DELETE FROM memberships WHERE user_id = ? AND group_id = ?').bind(uid, groupId).run();
  return json({ ok: true });
}

async function handleDeleteGroup(request, env, groupId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const membership = await getMembership(env, uid, groupId);
  if (!membership || membership.role !== 'commissioner') {
    return json({ error: 'Only the commissioner can delete the group' }, 403);
  }
  await env.DB.prepare('DELETE FROM pool_payments WHERE group_id = ?').bind(groupId).run();
  await env.DB.prepare('DELETE FROM picks WHERE group_id = ?').bind(groupId).run();
  await env.DB.prepare('DELETE FROM memberships WHERE group_id = ?').bind(groupId).run();
  await env.DB.prepare('DELETE FROM groups WHERE id = ?').bind(groupId).run();
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

async function findWeek(env, seasonYear, weekNumber) {
  return env.DB.prepare('SELECT id FROM weeks WHERE season_year = ? AND week_number = ?')
    .bind(seasonYear, weekNumber).first();
}

async function weekGames(env, weekId) {
  const { results } = await env.DB.prepare('SELECT * FROM games WHERE week_id = ? ORDER BY kickoff_time, id')
    .bind(weekId).all();
  return results;
}

// A player's picks for one week, keyed by game id. Picks are universal: one set per player
// (group_id IS NULL) counts in every group and on the community leaderboard.
async function picksForWeek(env, userId, weekId) {
  const { results } = await env.DB.prepare(
    `SELECT p.game_id, p.picked_team FROM picks p JOIN games g ON g.id = p.game_id
     WHERE p.user_id = ? AND g.week_id = ? AND p.group_id IS NULL`
  ).bind(userId, weekId).all();
  return Object.fromEntries(results.map((p) => [p.game_id, p.picked_team]));
}

function hasKickedOff(game, now = Date.now()) {
  return new Date(game.kickoff_time).getTime() <= now;
}

function isRight(game, pick) {
  return !!pick && !!game.final_winner && pick === game.final_winner;
}

function isWrong(game, pick) {
  return !!pick && !!game.final_winner && pick !== game.final_winner;
}

// GET /api/picks?season=&week= — your own picks for a week
async function handleGetMyPicks(request, env) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const url = new URL(request.url);
  const week = await findWeek(env, url.searchParams.get('season'), url.searchParams.get('week'));
  if (!week) return json({ games: [] });

  const games = await weekGames(env, week.id);
  const mine = await picksForWeek(env, uid, week.id);
  const now = Date.now();
  return json({
    games: games.map((g) => ({ ...g, picked_team: mine[g.id] || null, locked: hasKickedOff(g, now) })),
  });
}

// Kept so older copies of the site keep working; picks are universal now
async function handleGetPicks(request, env, groupId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const membership = await getMembership(env, uid, groupId);
  if (!membership) return json({ error: 'Not a member of this group' }, 403);
  return handleGetMyPicks(request, env);
}

async function handleSubmitPick(request, env) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const { game_id, picked_team } = await request.json();
  if (!game_id || !picked_team) return json({ error: 'game_id and picked_team are required' }, 400);

  const game = await env.DB.prepare('SELECT kickoff_time, home_team, away_team FROM games WHERE id = ?')
    .bind(game_id).first();
  if (!game) return json({ error: 'Game not found' }, 404);
  if (picked_team !== game.home_team && picked_team !== game.away_team) {
    return json({ error: "That team isn't playing in this game" }, 400);
  }
  if (hasKickedOff(game)) {
    return json({ error: 'This game has already kicked off — the pick is locked' }, 409);
  }

  const existing = await env.DB.prepare(
    'SELECT id FROM picks WHERE user_id = ? AND game_id = ? AND group_id IS NULL'
  ).bind(uid, game_id).first();

  if (existing) {
    await env.DB.prepare("UPDATE picks SET picked_team = ?, updated_at = datetime('now') WHERE id = ?")
      .bind(picked_team, existing.id).run();
  } else {
    await env.DB.prepare('INSERT INTO picks (user_id, game_id, group_id, picked_team) VALUES (?, ?, NULL, ?)')
      .bind(uid, game_id, picked_team).run();
  }

  return json({ ok: true });
}

// GET /api/groups/:id/members/:userId/picks?season=&week=
// Another group member's picks next to yours. Their pick on a game stays hidden
// until that game kicks off, so nobody can copy picks before the games.
async function handleGetMemberPicks(request, env, groupId, targetId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  if (!(await getMembership(env, uid, groupId))) return json({ error: 'Not a member of this group' }, 403);
  if (!(await getMembership(env, targetId, groupId))) return json({ error: "That player isn't in this group" }, 404);

  const member = await env.DB.prepare('SELECT id, name FROM users WHERE id = ?').bind(targetId).first();
  const url = new URL(request.url);
  const week = await findWeek(env, url.searchParams.get('season'), url.searchParams.get('week'));
  if (!week) return json({ member, games: [], summary: { right: 0, wrong: 0 } });

  const isSelf = String(targetId) === String(uid);
  const games = await weekGames(env, week.id);
  const theirs = await picksForWeek(env, targetId, week.id);
  const mine = isSelf ? theirs : await picksForWeek(env, uid, week.id);
  const now = Date.now();

  let right = 0;
  let wrong = 0;
  const rows = games.map((g) => {
    const started = hasKickedOff(g, now);
    const reveal = isSelf || started;
    const theirPick = theirs[g.id] || null;
    if (reveal && isRight(g, theirPick)) right++;
    if (reveal && isWrong(g, theirPick)) wrong++;
    return {
      ...g,
      locked: started,
      their_pick: reveal ? theirPick : null,
      hidden: !reveal,
      has_pick: !!theirPick,
      my_pick: mine[g.id] || null,
    };
  });

  return json({ member, is_self: isSelf, games: rows, summary: { right, wrong } });
}

// ---------- standings ----------

// Right/wrong counts per player for a week (or the whole season), from universal picks
const SCORE_SUBQUERY = `
  SELECT p.user_id,
         SUM(CASE WHEN g.final_winner IS NOT NULL AND p.picked_team = g.final_winner THEN 1 ELSE 0 END) AS points,
         SUM(CASE WHEN g.final_winner IS NOT NULL AND p.picked_team <> g.final_winner THEN 1 ELSE 0 END) AS wrong
  FROM picks p
  JOIN games g ON g.id = p.game_id
  JOIN weeks w ON w.id = g.week_id
  WHERE p.group_id IS NULL AND w.season_year = ?1 AND (?2 = 1 OR w.week_number = ?3)
  GROUP BY p.user_id`;

function scoreParams(url) {
  const type = url.searchParams.get('type') === 'season' ? 'season' : 'weekly';
  const seasonYear = Number(url.searchParams.get('season')) || currentNflSeason();
  const weekNumber = Number(url.searchParams.get('week')) || 0;
  return { type, seasonYear, isSeason: type === 'season' ? 1 : 0, weekNumber };
}

// Standard competition ranking: 1, 2, 2, 4 — players tied on points share a rank
function withRanks(rows) {
  let rank = 0;
  return rows.map((r, i) => {
    if (i === 0 || r.points !== rows[i - 1].points) rank = i + 1;
    return { ...r, rank };
  });
}

async function handleStandings(request, env, groupId) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);
  const membership = await getMembership(env, uid, groupId);
  if (!membership) return json({ error: 'Not a member of this group' }, 403);

  const { type, seasonYear, isSeason, weekNumber } = scoreParams(new URL(request.url));
  // picks_made counts picks only (never which team), so it's safe to show before kickoff
  const { results } = await env.DB.prepare(
    `SELECT u.id, u.name, m.role, COALESCE(s.points, 0) AS points, COALESCE(s.wrong, 0) AS wrong,
            COALESCE(pc.picks_made, 0) AS picks_made
     FROM memberships m
     JOIN users u ON u.id = m.user_id
     LEFT JOIN (${SCORE_SUBQUERY}) AS s ON s.user_id = u.id
     LEFT JOIN (
       SELECT p.user_id, COUNT(*) AS picks_made
       FROM picks p JOIN games g ON g.id = p.game_id JOIN weeks w ON w.id = g.week_id
       WHERE p.group_id IS NULL AND w.season_year = ?1 AND w.week_number = ?3
       GROUP BY p.user_id
     ) AS pc ON pc.user_id = u.id
     WHERE m.group_id = ?4
     ORDER BY points DESC, wrong ASC, u.name`
  ).bind(seasonYear, isSeason, weekNumber, groupId).all();

  let weekInfo = null;
  if (!isSeason) {
    weekInfo = await env.DB.prepare(
      `SELECT COUNT(*) AS games_total,
              COALESCE(SUM(CASE WHEN g.status IN ('FT', 'AOT', 'CANC') THEN 1 ELSE 0 END), 0) AS games_done
       FROM games g JOIN weeks w ON w.id = g.week_id
       WHERE w.season_year = ? AND w.week_number = ?`
    ).bind(seasonYear, weekNumber).first();
  }

  return json({ type, week_info: weekInfo, standings: withRanks(results) });
}

// GET /api/leaderboard?type=weekly|season&season=&week= — everyone on Tossup.
// Strangers only ever get a short public name ("Parker W."), never the full name.
async function handleLeaderboard(request, env) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);

  const { type, seasonYear, isSeason, weekNumber } = scoreParams(new URL(request.url));
  const { results } = await env.DB.prepare(
    `SELECT u.id, u.name, s.points, s.wrong
     FROM (${SCORE_SUBQUERY}) AS s
     JOIN users u ON u.id = s.user_id
     ORDER BY s.points DESC, s.wrong ASC, u.id`
  ).bind(seasonYear, isSeason, weekNumber).all();

  const ranked = withRanks(results).map((r) => ({
    rank: r.rank,
    name: publicName(r.name),
    points: r.points,
    wrong: r.wrong,
    is_me: r.id === uid,
  }));
  const me = ranked.find((r) => r.is_me) || null;
  return json({ type, total_players: ranked.length, me, leaders: ranked.slice(0, 100) });
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

  // One row per current member for this week (one query, however big the group is)
  await env.DB.prepare(
    `INSERT INTO pool_payments (group_id, week_id, user_id, amount_owed)
     SELECT ?, ?, user_id, ? FROM memberships WHERE group_id = ?
     ON CONFLICT (group_id, week_id, user_id) DO NOTHING`
  ).bind(groupId, week.id, group.pool_amount_per_person, groupId).run();

  // Only people still in the group — someone who was removed or left drops off the list
  const { results: payments } = await env.DB.prepare(
    `SELECT u.id, u.name, pp.paid, pp.amount_owed
     FROM pool_payments pp
     JOIN users u ON u.id = pp.user_id
     JOIN memberships m ON m.user_id = pp.user_id AND m.group_id = pp.group_id
     WHERE pp.group_id = ? AND pp.week_id = ?
     ORDER BY pp.paid, u.name COLLATE NOCASE`
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
    `UPDATE pool_payments SET paid = 1, confirmed_at = datetime('now') WHERE group_id = ? AND week_id = ? AND user_id = ?`
  ).bind(groupId, week.id, userId).run();

  return json({ ok: true });
}

// ---------- NFL game sync (nflverse) ----------
// Schedule and final scores come from nflverse's public games.csv — free, no API key,
// updated every few minutes during the season. The whole season is written in two queries.

const NFLVERSE_GAMES_URLS = [
  'https://raw.githubusercontent.com/nflverse/nfldata/master/data/games.csv',
  'https://cdn.jsdelivr.net/gh/nflverse/nfldata@master/data/games.csv', // backup mirror
];

// nflverse uses team codes; picks and scoring use full names.
const NFL_TEAMS = {
  ARI: ['Arizona Cardinals', 'ARI'], ATL: ['Atlanta Falcons', 'ATL'], BAL: ['Baltimore Ravens', 'BAL'],
  BUF: ['Buffalo Bills', 'BUF'], CAR: ['Carolina Panthers', 'CAR'], CHI: ['Chicago Bears', 'CHI'],
  CIN: ['Cincinnati Bengals', 'CIN'], CLE: ['Cleveland Browns', 'CLE'], DAL: ['Dallas Cowboys', 'DAL'],
  DEN: ['Denver Broncos', 'DEN'], DET: ['Detroit Lions', 'DET'], GB: ['Green Bay Packers', 'GB'],
  HOU: ['Houston Texans', 'HOU'], IND: ['Indianapolis Colts', 'IND'], JAX: ['Jacksonville Jaguars', 'JAX'],
  KC: ['Kansas City Chiefs', 'KC'], LA: ['Los Angeles Rams', 'LAR'], LAC: ['Los Angeles Chargers', 'LAC'],
  LV: ['Las Vegas Raiders', 'LV'], MIA: ['Miami Dolphins', 'MIA'], MIN: ['Minnesota Vikings', 'MIN'],
  NE: ['New England Patriots', 'NE'], NO: ['New Orleans Saints', 'NO'], NYG: ['New York Giants', 'NYG'],
  NYJ: ['New York Jets', 'NYJ'], PHI: ['Philadelphia Eagles', 'PHI'], PIT: ['Pittsburgh Steelers', 'PIT'],
  SEA: ['Seattle Seahawks', 'SEA'], SF: ['San Francisco 49ers', 'SF'], TB: ['Tampa Bay Buccaneers', 'TB'],
  TEN: ['Tennessee Titans', 'TEN'], WAS: ['Washington Commanders', 'WAS'],
};

function teamInfo(code) {
  const team = NFL_TEAMS[code];
  return team ? { name: team[0], abbr: team[1] } : { name: code, abbr: code };
}

// An NFL season is named for the year it starts: Jan/Feb 2027 games belong to the 2026 season.
function currentNflSeason(now = new Date()) {
  const year = now.getUTCFullYear();
  return now.getUTCMonth() < 2 ? year - 1 : year;
}

// Day of the month of the nth Sunday (monthIndex is 0-based)
function nthSunday(year, monthIndex, n) {
  const firstDay = new Date(Date.UTC(year, monthIndex, 1)).getUTCDay();
  return 1 + ((7 - firstDay) % 7) + (n - 1) * 7;
}

// US Eastern daylight time runs from the 2nd Sunday of March to the 1st Sunday of November
function isEasternDaylightTime(year, month, day) {
  if (month < 3 || month > 11) return false;
  if (month > 3 && month < 11) return true;
  if (month === 3) return day >= nthSunday(year, 2, 2);
  return day < nthSunday(year, 10, 1);
}

// nflverse lists every kickoff (international games too) in US Eastern time
function easternToUtcIso(dateStr, timeStr) {
  const [year, month, day] = dateStr.split('-').map(Number);
  const [hour, minute] = (timeStr || '13:00').split(':').map(Number);
  const offsetHours = isEasternDaylightTime(year, month, day) ? 4 : 5;
  return new Date(Date.UTC(year, month - 1, day, hour + offsetHours, minute)).toISOString();
}

// Splits one CSV line, handling quoted fields like "Stadium, City"
function parseCsvLine(line) {
  const fields = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') { field += '"'; i++; }
      else if (ch === '"') inQuotes = false;
      else field += ch;
    } else if (ch === '"') inQuotes = true;
    else if (ch === ',') { fields.push(field); field = ''; }
    else field += ch;
  }
  fields.push(field);
  return fields;
}

async function fetchGamesCsv() {
  let lastError;
  for (const url of NFLVERSE_GAMES_URLS) {
    try {
      const res = await fetch(url, { headers: { 'User-Agent': 'Tossup (tossup.me)' } });
      if (res.ok) return await res.text();
      lastError = new Error(`${new URL(url).hostname} returned HTTP ${res.status}`);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError;
}

// Returns this season's regular-season games from games.csv as plain objects.
// Only the season's own rows are parsed (they sit at the end of a ~2 MB file).
function extractSeasonRows(text, season) {
  const headerEnd = text.indexOf('\n');
  const header = parseCsvLine(text.slice(0, headerEnd).replace(/\r$/, ''));
  const col = Object.fromEntries(header.map((name, i) => [name, i]));
  for (const needed of ['game_id', 'season', 'game_type', 'week', 'gameday', 'gametime', 'away_team', 'away_score', 'home_team', 'home_score', 'overtime']) {
    if (!(needed in col)) throw new Error(`games.csv is missing the "${needed}" column`);
  }

  const sectionStart = text.indexOf(`\n${season}_`);
  if (sectionStart === -1) return [];

  const rows = [];
  for (const rawLine of text.slice(sectionStart + 1).split('\n')) {
    const line = rawLine.replace(/\r$/, '');
    if (!line) continue;
    const f = parseCsvLine(line);
    if (f[col.season] !== String(season) || f[col.game_type] !== 'REG') continue;
    rows.push({
      gameId: f[col.game_id],
      week: Number(f[col.week]),
      gameday: f[col.gameday],
      gametime: f[col.gametime],
      away: f[col.away_team],
      home: f[col.home_team],
      awayScore: f[col.away_score],
      homeScore: f[col.home_score],
      overtime: f[col.overtime],
    });
  }
  return rows;
}

// Turns one games.csv row into the flat shape our games table stores
function toGameRow(r, season) {
  if (!r.week || !r.gameday || !r.home || !r.away) return null;
  const home = teamInfo(r.home);
  const away = teamInfo(r.away);
  const played = r.homeScore !== '' && r.awayScore !== '';
  const homeScore = played ? Number(r.homeScore) : null;
  const awayScore = played ? Number(r.awayScore) : null;

  let finalWinner = null;
  if (played) {
    if (homeScore > awayScore) finalWinner = home.name;
    else if (awayScore > homeScore) finalWinner = away.name;
    // a tie leaves final_winner null — nobody's pick scores that game
  }

  return {
    id: `nflverse:${r.gameId}`,
    season: Number(season),
    week: r.week,
    home: home.name,
    home_abbr: home.abbr,
    away: away.name,
    away_abbr: away.abbr,
    kickoff: easternToUtcIso(r.gameday, r.gametime),
    status: played ? (r.overtime === '1' ? 'AOT' : 'FT') : 'NS',
    home_score: homeScore,
    away_score: awayScore,
    winner: finalWinner,
  };
}

async function syncNflGames(env, season) {
  const seasonYear = Number(season) || currentNflSeason();
  const text = await fetchGamesCsv();
  const rows = extractSeasonRows(text, seasonYear).map((r) => toGameRow(r, seasonYear)).filter(Boolean);
  if (rows.length === 0) return { seasonYear, synced: 0 };

  // Everything is passed as one JSON parameter and unpacked by SQLite's json_each,
  // so the whole season is written in two queries instead of one per game.
  const payload = JSON.stringify(rows);

  await env.DB.prepare(
    `INSERT OR IGNORE INTO weeks (season_year, week_number)
     SELECT DISTINCT json_extract(value, '$.season'), json_extract(value, '$.week') FROM json_each(?1)`
  ).bind(payload).run();

  // The DO UPDATE ... WHERE clause skips rows that haven't changed, so a sync
  // where nothing happened writes nothing.
  const result = await env.DB.prepare(
    `INSERT INTO games (week_id, source_game_id, home_team, home_team_abbr, away_team, away_team_abbr,
                        kickoff_time, status, home_score, away_score, final_winner)
     SELECT w.id,
            json_extract(j.value, '$.id'),
            json_extract(j.value, '$.home'),
            json_extract(j.value, '$.home_abbr'),
            json_extract(j.value, '$.away'),
            json_extract(j.value, '$.away_abbr'),
            json_extract(j.value, '$.kickoff'),
            json_extract(j.value, '$.status'),
            json_extract(j.value, '$.home_score'),
            json_extract(j.value, '$.away_score'),
            json_extract(j.value, '$.winner')
     FROM json_each(?1) AS j
     JOIN weeks AS w
       ON w.season_year = json_extract(j.value, '$.season')
      AND w.week_number = json_extract(j.value, '$.week')
     WHERE true
     ON CONFLICT (source_game_id) WHERE source_game_id IS NOT NULL DO UPDATE SET
       week_id = excluded.week_id,
       home_team = excluded.home_team,
       home_team_abbr = excluded.home_team_abbr,
       away_team = excluded.away_team,
       away_team_abbr = excluded.away_team_abbr,
       kickoff_time = excluded.kickoff_time,
       status = excluded.status,
       home_score = excluded.home_score,
       away_score = excluded.away_score,
       final_winner = excluded.final_winner
     WHERE games.week_id IS NOT excluded.week_id
        OR games.kickoff_time IS NOT excluded.kickoff_time
        OR games.status IS NOT excluded.status
        OR games.home_score IS NOT excluded.home_score
        OR games.away_score IS NOT excluded.away_score
        OR games.final_winner IS NOT excluded.final_winner
        OR games.home_team IS NOT excluded.home_team
        OR games.away_team IS NOT excluded.away_team`
  ).bind(payload).run();

  return { seasonYear, synced: rows.length, changed: result.meta?.changes ?? null };
}

async function handleSyncNfl(request, env) {
  const uid = await getAuthedUserId(request, env);
  if (!uid) return json({ error: 'Not authenticated' }, 401);

  // Cap manual syncs app-wide so nobody can hammer the data source (the cron keeps data fresh anyway)
  if (await tooManyRecentEvents(env, 'manual-sync', 5, 10)) {
    return json({ error: 'Sync was run recently. Try again in a few minutes.' }, 429);
  }
  await recordEvent(env, 'manual-sync');

  const url = new URL(request.url);
  const season = url.searchParams.get('season') || url.searchParams.get('year');

  try {
    const result = await syncNflGames(env, season);
    return json({ ok: true, ...result });
  } catch (err) {
    return json({ error: 'Sync failed', detail: String(err) }, 500);
  }
}

// The week people should be looking at: the week of the next game that isn't over.
// Once a week's last game finishes, this rolls forward to the next week.
async function handleCurrentWeek(request, env) {
  const season = currentNflSeason();
  const next = await env.DB.prepare(
    `SELECT w.season_year, w.week_number FROM games g JOIN weeks w ON w.id = g.week_id
     WHERE w.season_year = ? AND g.status NOT IN ('FT', 'AOT', 'CANC')
     ORDER BY g.kickoff_time LIMIT 1`
  ).bind(season).first();
  if (next) return json({ season: next.season_year, week: next.week_number });

  const last = await env.DB.prepare(
    `SELECT w.season_year, w.week_number FROM games g JOIN weeks w ON w.id = g.week_id
     WHERE w.season_year = ? ORDER BY w.week_number DESC LIMIT 1`
  ).bind(season).first();
  if (last) return json({ season: last.season_year, week: last.week_number });

  return json({ season, week: 1 });
}

// ---------- router ----------

async function route(request, env) {
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

      const inviteMatch = path.match(/^\/api\/invite\/([A-Za-z0-9]{1,12})$/);
      if (inviteMatch && method === 'GET') return handleInvitePreview(request, env, inviteMatch[1]);

      const groupMatch = path.match(/^\/api\/groups\/(\d+)$/);
      if (groupMatch && method === 'GET') return handleGetGroup(request, env, groupMatch[1]);
      if (groupMatch && method === 'PATCH') return handleUpdateGroup(request, env, groupMatch[1]);
      if (groupMatch && method === 'DELETE') return handleDeleteGroup(request, env, groupMatch[1]);

      const memberMatch = path.match(/^\/api\/groups\/(\d+)\/members\/(\d+)$/);
      if (memberMatch && method === 'DELETE') return handleRemoveMember(request, env, memberMatch[1], memberMatch[2]);

      const leaveMatch = path.match(/^\/api\/groups\/(\d+)\/leave$/);
      if (leaveMatch && method === 'POST') return handleLeaveGroup(request, env, leaveMatch[1]);

      const picksMatch = path.match(/^\/api\/groups\/(\d+)\/picks$/);
      if (picksMatch && method === 'GET') return handleGetPicks(request, env, picksMatch[1]);
      if (path === '/api/picks' && method === 'POST') return handleSubmitPick(request, env);
      if (path === '/api/picks' && method === 'GET') return handleGetMyPicks(request, env);
      if (path === '/api/leaderboard' && method === 'GET') return handleLeaderboard(request, env);

      const memberPicksMatch = path.match(/^\/api\/groups\/(\d+)\/members\/(\d+)\/picks$/);
      if (memberPicksMatch && method === 'GET') {
        return handleGetMemberPicks(request, env, memberPicksMatch[1], memberPicksMatch[2]);
      }

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

      if (path === '/api/sync/nfl' && method === 'POST') return handleSyncNfl(request, env);
      if (path === '/api/current-week' && method === 'GET') return handleCurrentWeek(request, env);

      return json({ error: 'Not found' }, 404);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    const allowOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: { ...CORS_HEADERS, 'Access-Control-Allow-Origin': allowOrigin } });
    }

    let response;
    try {
      // Awaited here so any handler error is caught (a returned-but-not-awaited promise would escape)
      response = await route(request, env);
    } catch (err) {
      console.error('Unhandled error:', request.method, new URL(request.url).pathname, err);
      response = json({ error: 'Something went wrong on our end. Try again in a moment.' }, 500);
    }
    response.headers.set('Access-Control-Allow-Origin', allowOrigin);
    return response;
  },

  // Runs on the schedule set in wrangler.toml — keeps this season's games and scores fresh
  async scheduled(event, env, ctx) {
    ctx.waitUntil(Promise.allSettled([
      syncNflGames(env),
      env.DB.prepare("DELETE FROM rate_limit_events WHERE created_at < datetime('now', '-1 day')").run(),
    ]));
  },
};
