-- Run this once against your LIVE database to switch the games table from ESPN to API-Sports.
-- (Safe to run: the games table is still empty because the ESPN sync never succeeded.)
--
-- wrangler d1 execute pickem-pool --remote --file=migration_002_api_sports.sql

DROP INDEX IF EXISTS idx_games_espn_event;
ALTER TABLE games RENAME COLUMN espn_event_id TO source_game_id;
CREATE UNIQUE INDEX idx_games_source_game ON games(source_game_id) WHERE source_game_id IS NOT NULL;

ALTER TABLE games ADD COLUMN status TEXT NOT NULL DEFAULT 'NS';
ALTER TABLE games ADD COLUMN home_score INTEGER;
ALTER TABLE games ADD COLUMN away_score INTEGER;
