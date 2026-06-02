CREATE TABLE IF NOT EXISTS access_logs (
  id TEXT PRIMARY KEY,
  received_at TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  client_ip TEXT NOT NULL DEFAULT '',
  ip_hash TEXT NOT NULL DEFAULT '',
  country TEXT NOT NULL DEFAULT '',
  region TEXT NOT NULL DEFAULT '',
  city TEXT NOT NULL DEFAULT '',
  colo TEXT NOT NULL DEFAULT '',
  method TEXT NOT NULL DEFAULT 'GET',
  host TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '/',
  query TEXT NOT NULL DEFAULT '',
  status_code INTEGER NOT NULL DEFAULT 0,
  user_agent TEXT NOT NULL DEFAULT '',
  referer TEXT NOT NULL DEFAULT '',
  cf_ray TEXT NOT NULL DEFAULT '',
  request_id TEXT NOT NULL DEFAULT '',
  response_bytes INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT 'worker',
  raw_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_access_logs_occurred_at ON access_logs (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_logs_country ON access_logs (country);
CREATE INDEX IF NOT EXISTS idx_access_logs_path ON access_logs (path);
CREATE INDEX IF NOT EXISTS idx_access_logs_status_code ON access_logs (status_code);
