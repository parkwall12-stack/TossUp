-- Run this once against your LIVE database to catch it up to the new schema.
-- (Your existing games table was created before these columns existed.)
--
-- wrangler d1 execute pickem-pool --remote --file=migration_001_espn_sync.sql

ALTER TABLE games ADD COLUMN espn_event_id TEXT;
ALTER TABLE games ADD COLUMN home_team_abbr TEXT;
ALTER TABLE games ADD COLUMN away_team_abbr TEXT;

CREATE UNIQUE INDEX idx_games_espn_event ON games(espn_event_id) WHERE espn_event_id IS NOT NULL;
