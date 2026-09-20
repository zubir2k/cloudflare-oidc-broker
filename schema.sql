-- ============================================================
-- cloudflare-oidc-broker: canonical schema (v3)
-- Run this on a fresh D1 database.
-- For existing deployments, use migrate.sql instead.
-- ============================================================

-- Downstream client applications
CREATE TABLE IF NOT EXISTS clients (
    client_id     TEXT PRIMARY KEY,
    client_name   TEXT NOT NULL,
    client_secret TEXT,                          -- NULL = public client (PKCE only)
    redirect_uris TEXT NOT NULL DEFAULT '[]',    -- JSON array of allowed redirect URIs
    provider      TEXT NOT NULL DEFAULT 'google',-- Upstream provider: google | microsoft | github | apple
    require_pkce  INTEGER NOT NULL DEFAULT 1,     -- 1 = S256 mandatory, 0 = exempt (legacy clients)
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- User directory and per-app mappings
CREATE TABLE IF NOT EXISTS user_mappings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    email        TEXT NOT NULL,
    client_id    TEXT NOT NULL DEFAULT '*',      -- '*' = global fallback across all apps
    username     TEXT NOT NULL,
    display_name TEXT,
    google_sub   TEXT,                           -- stores any upstream provider sub
    is_active    INTEGER NOT NULL DEFAULT 1,
    last_login   DATETIME,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(email, client_id)
);
