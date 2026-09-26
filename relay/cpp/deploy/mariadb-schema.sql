-- R2R "Central Square" dashboard schema.
--
-- Apply with:  sudo mariadb < deploy/mariadb-schema.sql
--
-- WHAT LIVES HERE
--   Aggregate counters, one sample per relay per poll, plus a rollup row the
--   dashboard front page can read with a single SELECT.
--
-- WHAT MUST NEVER LIVE HERE
--   Recipient fingerprints, payloads, invite codes, per-message rows, client
--   addresses. None of it is exposed by the source endpoint and the syncer
--   copies an explicit field whitelist, so it cannot arrive here by accident.
--   Keep it that way: the relay's privacy guarantees are only as good as the
--   weakest system holding its data, and a dashboard is a soft target.

CREATE DATABASE IF NOT EXISTS r2r_main
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE r2r_main;

-- One row per relay per poll. This is the time series behind every graph.
CREATE TABLE IF NOT EXISTS node_metrics (
    id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sampled_at        DATETIME        NOT NULL,
    address           VARCHAR(64)     NOT NULL,
    node_id           VARCHAR(32)     NOT NULL DEFAULT '',
    reachable         TINYINT(1)      NOT NULL DEFAULT 0,
    latency_ms        INT UNSIGNED    NULL,
    version           VARCHAR(16)     NOT NULL DEFAULT '',
    uptime_seconds    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    peers_known       INT UNSIGNED    NOT NULL DEFAULT 0,
    peers_active      INT UNSIGNED    NOT NULL DEFAULT 0,
    connections       INT UNSIGNED    NOT NULL DEFAULT 0,
    clients           INT UNSIGNED    NOT NULL DEFAULT 0,
    relay_links       INT UNSIGNED    NOT NULL DEFAULT 0,
    tls_connections   INT UNSIGNED    NOT NULL DEFAULT 0,
    drops_stored      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    drop_bytes        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    drops_accepted    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    drops_rejected    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    identities        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    invites_open      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    invites_burned    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    frames_in         BIGINT UNSIGNED NOT NULL DEFAULT 0,
    frames_out        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    frames_forwarded  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    onion_peeled      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    UNIQUE KEY uniq_sample (address, sampled_at),
    KEY idx_sampled (sampled_at),
    KEY idx_address_time (address, sampled_at)
) ENGINE=InnoDB;

-- Current state of every relay we know about. Upserted, so the dashboard's
-- node list is a single unordered scan of a small table.
CREATE TABLE IF NOT EXISTS node_directory (
    address              VARCHAR(64)     NOT NULL PRIMARY KEY,
    node_id              VARCHAR(32)     NOT NULL DEFAULT '',
    is_self              TINYINT(1)      NOT NULL DEFAULT 0,
    tls                  TINYINT(1)      NOT NULL DEFAULT 0,
    reachable            TINYINT(1)      NOT NULL DEFAULT 0,
    version              VARCHAR(16)     NOT NULL DEFAULT '',
    latency_ms           INT UNSIGNED    NULL,
    uptime_seconds       BIGINT UNSIGNED NOT NULL DEFAULT 0,
    drops_stored         BIGINT UNSIGNED NOT NULL DEFAULT 0,
    identities           BIGINT UNSIGNED NOT NULL DEFAULT 0,
    peers_active         INT UNSIGNED    NOT NULL DEFAULT 0,
    first_seen           DATETIME        NOT NULL,
    last_checked         DATETIME        NOT NULL,
    last_reachable_at    DATETIME        NULL,
    consecutive_failures INT UNSIGNED    NOT NULL DEFAULT 0,
    KEY idx_reachable (reachable)
) ENGINE=InnoDB;

-- Single-row rollup. The dashboard's headline numbers come from here.
CREATE TABLE IF NOT EXISTS network_summary (
    id                TINYINT UNSIGNED NOT NULL PRIMARY KEY,
    updated_at        DATETIME        NOT NULL,
    nodes_known       INT UNSIGNED    NOT NULL DEFAULT 0,
    nodes_reachable   INT UNSIGNED    NOT NULL DEFAULT 0,
    drops_stored      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    drop_bytes        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    identities        BIGINT UNSIGNED NOT NULL DEFAULT 0,
    invites_open      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    invites_burned    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    connections       INT UNSIGNED    NOT NULL DEFAULT 0,
    relay_links       INT UNSIGNED    NOT NULL DEFAULT 0,
    frames_forwarded  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    onion_peeled      BIGINT UNSIGNED NOT NULL DEFAULT 0
) ENGINE=InnoDB;

-- Health of the syncer itself, so a silently dead timer is visible.
CREATE TABLE IF NOT EXISTS sync_runs (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    started_at      DATETIME     NOT NULL,
    duration_ms     INT UNSIGNED NOT NULL,
    nodes_polled    INT UNSIGNED NOT NULL DEFAULT 0,
    nodes_reachable INT UNSIGNED NOT NULL DEFAULT 0,
    ok              TINYINT(1)   NOT NULL DEFAULT 1,
    note            VARCHAR(255) NULL,
    KEY idx_started (started_at)
) ENGINE=InnoDB;

-- The syncer authenticates as the OS user that runs it, so there is no
-- password anywhere on disk to leak. It is granted no DDL and no access to
-- anything outside this database.
CREATE USER IF NOT EXISTS 'r2r'@'localhost' IDENTIFIED VIA unix_socket;
GRANT SELECT, INSERT, UPDATE, DELETE ON r2r_main.* TO 'r2r'@'localhost';

-- A read-only account for whatever renders the dashboard. Give the web tier
-- this one, never the writer.
CREATE USER IF NOT EXISTS 'r2r_dash'@'localhost' IDENTIFIED VIA unix_socket;
GRANT SELECT ON r2r_main.* TO 'r2r_dash'@'localhost';

FLUSH PRIVILEGES;
