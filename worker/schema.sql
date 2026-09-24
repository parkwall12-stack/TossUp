-- Pick'em pool database schema (Cloudflare D1 / SQLite)

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  venmo_handle TEXT,
  pick_mode TEXT NOT NULL DEFAULT 'global' CHECK (pick_mode IN ('global', 'per_group')),
  ad_free_until TEXT, -- NULL = ads on; a future date = ad-free until that renewal date
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  invite_code TEXT NOT NULL UNIQUE,
  commissioner_id INTEGER NOT NULL REFERENCES users(id),
  pool_enabled INTEGER NOT NULL DEFAULT 0,
  pool_amount_per_person REAL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE memberships (
  user_id INTEGER NOT NULL REFERENCES users(id),
  group_id INTEGER NOT NULL REFERENCES groups(id),
  role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('commissioner', 'member')),
  joined_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, group_id)
);

-- Weeks and games are global / shared across every group — same NFL schedule for everyone
CREATE TABLE weeks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  season_year INTEGER NOT NULL,
  week_number INTEGER NOT NULL,
  UNIQUE (season_year, week_number)
);

CREATE TABLE games (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  week_id INTEGER NOT NULL REFERENCES weeks(id),
  source_game_id TEXT, -- the data provider's game ID, e.g. "apisports:17377"
  home_team TEXT NOT NULL,
  home_team_abbr TEXT,
  away_team TEXT NOT NULL,
  away_team_abbr TEXT,
  kickoff_time TEXT NOT NULL, -- ISO 8601 UTC
  status TEXT NOT NULL DEFAULT 'NS', -- NS, Q1-Q4, HT, OT, FT, AOT, CANC, PST
  home_score INTEGER,
  away_score INTEGER,
  final_winner TEXT -- NULL until the game ends (and stays NULL for a tie)
);
CREATE UNIQUE INDEX idx_games_source_game ON games(source_game_id) WHERE source_game_id IS NOT NULL;

-- group_id NULL = a global pick (applies to every group the user is in)
-- group_id set  = a pick scoped to just that one group (per-group mode)
CREATE TABLE picks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  game_id INTEGER NOT NULL REFERENCES games(id),
  group_id INTEGER REFERENCES groups(id),
  picked_team TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Enforce "one pick per user per game" separately for the global row and each per-group row,
-- since SQLite treats NULLs as distinct in a normal UNIQUE constraint.
CREATE UNIQUE INDEX idx_picks_global ON picks(user_id, game_id) WHERE group_id IS NULL;
CREATE UNIQUE INDEX idx_picks_per_group ON picks(user_id, game_id, group_id) WHERE group_id IS NOT NULL;

CREATE TABLE pool_payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER NOT NULL REFERENCES groups(id),
  week_id INTEGER NOT NULL REFERENCES weeks(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  amount_owed REAL NOT NULL,
  paid INTEGER NOT NULL DEFAULT 0,
  confirmed_at TEXT,
  UNIQUE (group_id, week_id, user_id)
);

CREATE INDEX idx_games_week ON games(week_id);
CREATE INDEX idx_memberships_group ON memberships(group_id);
CREATE INDEX idx_memberships_user ON memberships(user_id);

-- Backs rate limiting on login and signup (see tooManyRecentEvents in the Worker)
CREATE TABLE rate_limit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  identifier TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_rate_limit_identifier ON rate_limit_events(identifier, created_at);
