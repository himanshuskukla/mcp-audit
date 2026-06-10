CREATE TABLE IF NOT EXISTS reports (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  version         TEXT    NOT NULL,
  os              TEXT    NOT NULL,
  arch            TEXT,
  node_ver        TEXT,
  clients         TEXT    NOT NULL,
  server_count    INTEGER NOT NULL,
  score           INTEGER NOT NULL,
  grade           TEXT    NOT NULL,
  live            INTEGER NOT NULL DEFAULT 0,
  findings        TEXT    NOT NULL,
  rules_fired     TEXT    NOT NULL,
  total_findings  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at);
CREATE INDEX IF NOT EXISTS idx_reports_grade ON reports(grade);
