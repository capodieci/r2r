#!/usr/bin/env python3
"""Pushes R2R relay metrics into MariaDB for the Central Square dashboard.

The relay keeps using SQLite. This reads the aggregate counters the relay
already publishes and writes them to MariaDB, where a web frontend can run
whatever joins and window functions it likes without ever touching the file a
live relay is writing to.

WHY THE HTTP ENDPOINT AND NOT THE SQLITE FILE
    /status.json is computed from the same SQLite database, by the process that
    owns it. Going through the relay means:
      * no second reader on a WAL database, so no lock contention on the hot
        path and no -shm/-wal permission problems,
      * no dependency on the database's on-disk layout or file location,
      * the syncer *cannot* read message rows even by mistake -- the endpoint
        does not expose them.
    If the dashboard ever needs an aggregate that is not published, add it to
    the relay's /status.json. Keep one process owning the database.

WHAT IS COPIED
    Only the fields in METRIC_FIELDS below: counters and gauges. No recipient
    fingerprints, no payloads, no invite codes, no client addresses. The
    whitelist is enforced in code, not by convention.

Usage:
    r2r-metrics-sync.py [--once] [--local URL] [--retention-days N] [--dry-run]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import ssl
import sys
import time
import urllib.error
import urllib.request

try:
    import pymysql
except ImportError:  # pragma: no cover
    sys.exit("python3-pymysql is not installed (apt install python3-pymysql)")

DEFAULT_LOCAL = "http://127.0.0.1:8787"
DEFAULT_SOCKET = "/run/mysqld/mysqld.sock"
DEFAULT_DB = "r2r_main"
DEFAULT_USER = "r2r"
POLL_TIMEOUT = 6.0
MAX_PARALLEL_POLLS = 8

# The privacy whitelist. A field absent from here never reaches MariaDB, no
# matter what a relay puts in its /status.json.
METRIC_FIELDS = (
    "uptime_seconds",
    "peers_known",
    "peers_active",
    "connections",
    "clients",
    "relay_links",
    "tls_connections",
    "drops_stored",
    "drop_bytes",
    "drops_accepted",
    "drops_rejected",
    "identities",
    "invites_open",
    "invites_burned",
    "frames_in",
    "frames_out",
    "frames_forwarded",
    "onion_peeled",
)

# /status.json spells uptime differently from the column name.
FIELD_ALIASES = {"uptime_seconds": "uptime"}


def log(msg: str) -> None:
    print(msg, flush=True)


def http_json(url: str, timeout: float = POLL_TIMEOUT):
    """GETs JSON. Returns (payload, latency_ms) or (None, None)."""
    req = urllib.request.Request(
        url, headers={"User-Agent": "r2r-metrics-sync/1.0", "Accept": "application/json"}
    )
    # Relays present certificates trusted only by their peers, and this is a
    # read of public counters over the loopback or a known address -- there is
    # no secret here to protect with chain validation.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status != 200:
                return None, None
            body = resp.read(1_000_000)
    except (urllib.error.URLError, OSError, ValueError):
        return None, None
    latency_ms = int((time.monotonic() - started) * 1000)
    try:
        return json.loads(body), latency_ms
    except json.JSONDecodeError:
        return None, None


def discover_nodes(local_url: str):
    """Returns (self_address, [(address, tls, is_self), ...]) from the local relay."""
    peers, _ = http_json(f"{local_url}/peers.json")
    if not peers:
        return None, []

    self_address = (peers.get("node") or {}).get("advertise") or ""
    nodes = []
    seen = set()

    if self_address:
        nodes.append((self_address, False, True))
        seen.add(self_address)

    for peer in peers.get("peers") or []:
        address = (peer.get("address") or "").strip()
        if not address or address in seen:
            continue
        seen.add(address)
        nodes.append((address, bool(peer.get("tls")), False))

    return self_address, nodes


def poll_node(address: str, tls: bool, is_self: bool, local_url: str):
    """Polls one relay's /status.json. Never raises."""
    # Reach ourselves over loopback rather than back in through our own public
    # address: fewer moving parts, and it works before DNS or the CDN is up.
    base = local_url if is_self else f"{'https' if tls else 'http'}://{address}"
    status, latency_ms = http_json(f"{base}/status.json")

    row = {
        "address": address,
        "node_id": "",
        "reachable": 0,
        "latency_ms": None,
        "version": "",
    }
    for column in METRIC_FIELDS:
        row[column] = 0

    if not status:
        return row

    row["reachable"] = 1
    row["latency_ms"] = latency_ms
    row["node_id"] = str(status.get("node_id", ""))[:32]
    row["version"] = str(status.get("version", ""))[:16]
    for column in METRIC_FIELDS:
        raw = status.get(FIELD_ALIASES.get(column, column), 0)
        try:
            row[column] = max(0, int(raw))
        except (TypeError, ValueError):
            row[column] = 0
    return row


def connect_db(args):
    return pymysql.connect(
        user=args.db_user,
        database=args.database,
        unix_socket=args.socket,
        charset="utf8mb4",
        autocommit=False,
    )


def write_rows(conn, sampled_at, rows, tls_by_address, self_address, retention_days):
    columns = ["sampled_at", "address", "node_id", "reachable", "latency_ms", "version"]
    columns += list(METRIC_FIELDS)
    placeholders = ", ".join(["%s"] * len(columns))
    insert_metrics = (
        f"INSERT INTO node_metrics ({', '.join(columns)}) VALUES ({placeholders}) "
        f"ON DUPLICATE KEY UPDATE reachable = VALUES(reachable)"
    )

    upsert_directory = """
        INSERT INTO node_directory
            (address, node_id, is_self, tls, reachable, version, latency_ms,
             uptime_seconds, drops_stored, identities, peers_active,
             first_seen, last_checked, last_reachable_at, consecutive_failures)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
            node_id     = IF(VALUES(node_id) <> '', VALUES(node_id), node_id),
            is_self     = VALUES(is_self),
            tls         = VALUES(tls),
            reachable   = VALUES(reachable),
            version     = IF(VALUES(version) <> '', VALUES(version), version),
            latency_ms  = VALUES(latency_ms),
            uptime_seconds = VALUES(uptime_seconds),
            drops_stored   = VALUES(drops_stored),
            identities     = VALUES(identities),
            peers_active   = VALUES(peers_active),
            last_checked   = VALUES(last_checked),
            last_reachable_at =
                IF(VALUES(reachable) = 1, VALUES(last_checked), last_reachable_at),
            consecutive_failures =
                IF(VALUES(reachable) = 1, 0, consecutive_failures + 1)
    """

    reachable_rows = [r for r in rows if r["reachable"]]
    summary = {
        "nodes_known": len(rows),
        "nodes_reachable": len(reachable_rows),
    }
    for column in ("drops_stored", "drop_bytes", "identities", "invites_open",
                   "invites_burned", "connections", "relay_links",
                   "frames_forwarded", "onion_peeled"):
        summary[column] = sum(r[column] for r in reachable_rows)

    upsert_summary = """
        INSERT INTO network_summary
            (id, updated_at, nodes_known, nodes_reachable, drops_stored, drop_bytes,
             identities, invites_open, invites_burned, connections, relay_links,
             frames_forwarded, onion_peeled)
        VALUES (1,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE
            updated_at=VALUES(updated_at), nodes_known=VALUES(nodes_known),
            nodes_reachable=VALUES(nodes_reachable), drops_stored=VALUES(drops_stored),
            drop_bytes=VALUES(drop_bytes), identities=VALUES(identities),
            invites_open=VALUES(invites_open), invites_burned=VALUES(invites_burned),
            connections=VALUES(connections), relay_links=VALUES(relay_links),
            frames_forwarded=VALUES(frames_forwarded), onion_peeled=VALUES(onion_peeled)
    """

    with conn.cursor() as cur:
        for row in rows:
            cur.execute(insert_metrics, [sampled_at] + [row[c] for c in columns[1:]])
            cur.execute(
                upsert_directory,
                (
                    row["address"], row["node_id"],
                    1 if row["address"] == self_address else 0,
                    1 if tls_by_address.get(row["address"]) else 0,
                    row["reachable"], row["version"], row["latency_ms"],
                    row["uptime_seconds"], row["drops_stored"], row["identities"],
                    row["peers_active"],
                    sampled_at, sampled_at,
                    sampled_at if row["reachable"] else None,
                    0 if row["reachable"] else 1,
                ),
            )

        cur.execute(
            upsert_summary,
            (
                sampled_at, summary["nodes_known"], summary["nodes_reachable"],
                summary["drops_stored"], summary["drop_bytes"], summary["identities"],
                summary["invites_open"], summary["invites_burned"],
                summary["connections"], summary["relay_links"],
                summary["frames_forwarded"], summary["onion_peeled"],
            ),
        )

        if retention_days > 0:
            cutoff = sampled_at - dt.timedelta(days=retention_days)
            cur.execute("DELETE FROM node_metrics WHERE sampled_at < %s", (cutoff,))
            cur.execute("DELETE FROM sync_runs WHERE started_at < %s", (cutoff,))

    conn.commit()
    return summary


def run_once(args) -> int:
    started_wall = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0)
    started = time.monotonic()

    self_address, nodes = discover_nodes(args.local)
    if not nodes:
        log("local relay is unreachable; nothing to sync")
        if not args.dry_run:
            try:
                conn = connect_db(args)
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO sync_runs (started_at, duration_ms, nodes_polled,"
                        " nodes_reachable, ok, note) VALUES (%s,%s,0,0,0,%s)",
                        (started_wall, int((time.monotonic() - started) * 1000),
                         "local relay unreachable"),
                    )
                conn.commit()
                conn.close()
            except Exception as exc:  # noqa: BLE001 - never let reporting kill the run
                log(f"could not record the failed run: {exc}")
        return 1

    tls_by_address = {address: tls for address, tls, _ in nodes}

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PARALLEL_POLLS) as pool:
        rows = list(pool.map(
            lambda n: poll_node(n[0], n[1], n[2], args.local), nodes))

    reachable = sum(r["reachable"] for r in rows)

    if args.dry_run:
        log(json.dumps(rows, indent=2, default=str))
        log(f"dry run: {reachable}/{len(rows)} relays reachable, nothing written")
        return 0

    try:
        conn = connect_db(args)
    except Exception as exc:  # noqa: BLE001
        log(f"cannot connect to MariaDB: {exc}")
        return 1

    try:
        summary = write_rows(conn, started_wall, rows, tls_by_address,
                             self_address, args.retention_days)
        duration_ms = int((time.monotonic() - started) * 1000)
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sync_runs (started_at, duration_ms, nodes_polled,"
                " nodes_reachable, ok, note) VALUES (%s,%s,%s,%s,1,NULL)",
                (started_wall, duration_ms, len(rows), reachable),
            )
        conn.commit()
        log(
            f"synced {reachable}/{len(rows)} relays in {duration_ms}ms "
            f"({summary['drops_stored']} payloads, {summary['identities']} identities "
            f"network-wide)"
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        conn.rollback()
        log(f"sync failed: {type(exc).__name__}: {exc}")
        return 1
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync R2R relay metrics into MariaDB")
    parser.add_argument("--local", default=DEFAULT_LOCAL,
                        help=f"local relay HTTP base URL (default {DEFAULT_LOCAL})")
    parser.add_argument("--socket", default=DEFAULT_SOCKET, help="MariaDB unix socket")
    parser.add_argument("--database", default=DEFAULT_DB)
    parser.add_argument("--db-user", default=DEFAULT_USER)
    parser.add_argument("--retention-days", type=int, default=30,
                        help="drop samples older than this (0 disables)")
    parser.add_argument("--interval", type=int, default=60,
                        help="seconds between runs when looping")
    parser.add_argument("--once", action="store_true",
                        help="run a single sync and exit (how the timer calls it)")
    parser.add_argument("--dry-run", action="store_true",
                        help="poll and print, write nothing")
    args = parser.parse_args()

    if args.once or args.dry_run:
        return run_once(args)

    while True:
        run_once(args)
        time.sleep(max(10, args.interval))


if __name__ == "__main__":
    sys.exit(main())
