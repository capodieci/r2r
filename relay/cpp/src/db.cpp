#include "db.hpp"

#include <sqlite3.h>

#include <cstdio>
#include <mutex>

#include "crypto.hpp"
#include "log.hpp"

namespace r2r {
namespace {

std::once_flag g_sqlite_init;

void ensure_sqlite_initialised() {
    // The amalgamation is compiled with SQLITE_OMIT_AUTOINIT.
    std::call_once(g_sqlite_init, [] {
        if (sqlite3_initialize() != SQLITE_OK)
            log::error("sqlite3_initialize() failed");
    });
}

constexpr int kSchemaVersion = 5;

}  // namespace

// ---------------------------------------------------------------- Stmt -----

class Db::Stmt {
public:
    Stmt(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &st_, nullptr) != SQLITE_OK) {
            log::error("sqlite prepare failed: ", sqlite3_errmsg(db), " | ", sql);
            st_ = nullptr;
        }
    }
    ~Stmt() { sqlite3_finalize(st_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    explicit operator bool() const { return st_ != nullptr; }
    sqlite3_stmt* raw() const { return st_; }

    Stmt& reset() {
        sqlite3_reset(st_);
        sqlite3_clear_bindings(st_);
        return *this;
    }
    Stmt& text(int i, std::string_view v) {
        sqlite3_bind_text(st_, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
        return *this;
    }
    Stmt& blob(int i, const void* p, std::size_t n) {
        if (n == 0) sqlite3_bind_zeroblob(st_, i, 0);
        else sqlite3_bind_blob64(st_, i, p, static_cast<sqlite3_uint64>(n), SQLITE_TRANSIENT);
        return *this;
    }
    Stmt& i64(int i, std::int64_t v) {
        sqlite3_bind_int64(st_, i, v);
        return *this;
    }
    Stmt& null(int i) {
        sqlite3_bind_null(st_, i);
        return *this;
    }

    int step() { return sqlite3_step(st_); }

    std::string col_text(int i) const {
        const auto* p = sqlite3_column_text(st_, i);
        if (!p) return {};
        return std::string(reinterpret_cast<const char*>(p),
                           static_cast<std::size_t>(sqlite3_column_bytes(st_, i)));
    }
    std::int64_t col_i64(int i) const { return sqlite3_column_int64(st_, i); }
    util::Bytes col_blob(int i) const {
        const auto* p = static_cast<const std::uint8_t*>(sqlite3_column_blob(st_, i));
        const int n = sqlite3_column_bytes(st_, i);
        if (!p || n <= 0) return {};
        return util::Bytes(p, p + n);
    }

private:
    sqlite3_stmt* st_{nullptr};
};

// ------------------------------------------------------------------ Db -----

Db::Db() = default;
Db::~Db() { close(); }

bool Db::open(const std::string& path) {
    ensure_sqlite_initialised();
    std::lock_guard<std::mutex> lock(mu_);

    if (!util::make_dirs(util::dirname_of(path), 0700)) {
        log::error("cannot create database directory: ", util::dirname_of(path));
        return false;
    }

    const int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    if (sqlite3_open_v2(path.c_str(), &db_, flags, nullptr) != SQLITE_OK) {
        log::error("cannot open database ", path, ": ",
                   db_ ? sqlite3_errmsg(db_) : "out of memory");
        close();
        return false;
    }
    sqlite3_busy_timeout(db_, 5000);

    exec("PRAGMA journal_mode=WAL");
    exec("PRAGMA synchronous=NORMAL");
    exec("PRAGMA foreign_keys=ON");
    exec("PRAGMA temp_store=MEMORY");
    exec("PRAGMA cache_size=-8000");   // ~8 MiB page cache
    exec("PRAGMA secure_delete=ON");   // overwrite freed pages holding ciphertext

    if (!migrate()) {
        close();
        return false;
    }
    return true;
}

void Db::close() {
    stmts_.clear();
    if (db_) {
        sqlite3_close_v2(db_);
        db_ = nullptr;
    }
}

void Db::set_quota(std::int64_t max_drops, std::int64_t max_bytes) {
    std::lock_guard<std::mutex> lock(mu_);
    max_drops_per_recipient_ = max_drops;
    max_bytes_per_recipient_ = max_bytes;
}

void Db::set_common_pool(std::int64_t max_bytes) {
    std::lock_guard<std::mutex> lock(mu_);
    common_pool_bytes_ = max_bytes;
}

std::int64_t Db::allowance_locked(const std::string& fingerprint) {
    std::int64_t allowance = max_bytes_per_recipient_;
    if (auto* q = cached("SELECT max_bytes FROM quotas WHERE fingerprint=?1")) {
        q->text(1, fingerprint);
        if (q->step() == SQLITE_ROW) allowance = q->col_i64(0);
        q->reset();
    }
    if (auto* q = cached("SELECT IFNULL(SUM(bytes),0) FROM rentals"
                         " WHERE fingerprint=?1 AND state='active' AND paid_until>?2")) {
        q->text(1, fingerprint).i64(2, util::now_unix());
        if (q->step() == SQLITE_ROW) allowance += q->col_i64(0);
        q->reset();
    }
    return allowance;
}

std::int64_t Db::free_tier_bytes_locked() {
    const std::int64_t now = util::now_unix();
    if (free_tier_memo_ < 0 || now - free_tier_memo_at_ > 30) {
        // Identities with a custom quota or an active rental are not free
        // tier: their storage is governed by that allowance (and, for
        // rentals, accounted against the market pool).
        auto* q = cached(
            "SELECT"
            " (SELECT IFNULL(SUM(LENGTH(payload)),0) FROM drops"
            "   WHERE recipient NOT IN (SELECT fingerprint FROM quotas"
            "     UNION SELECT fingerprint FROM rentals"
            "      WHERE state='active' AND paid_until>strftime('%s','now')))"
            "+(SELECT IFNULL(SUM(LENGTH(data)),0) FROM journal"
            "   WHERE fingerprint NOT IN (SELECT fingerprint FROM quotas"
            "     UNION SELECT fingerprint FROM rentals"
            "      WHERE state='active' AND paid_until>strftime('%s','now')))"
            "+(SELECT IFNULL(SUM(size),0) FROM blobs"
            "   WHERE owner NOT IN (SELECT fingerprint FROM quotas"
            "     UNION SELECT fingerprint FROM rentals"
            "      WHERE state='active' AND paid_until>strftime('%s','now')))");
        if (q && q->step() == SQLITE_ROW) {
            free_tier_memo_ = q->col_i64(0);
            free_tier_memo_at_ = now;
        }
        if (q) q->reset();
    }
    return free_tier_memo_ < 0 ? 0 : free_tier_memo_;
}

bool Db::common_pool_exceeded(const std::string& fingerprint, std::int64_t add_bytes) {
    if (common_pool_bytes_ <= 0) return false;

    // An identity with its own allowance -- a custom quota or a paid rental
    // -- is not drawing from the common pool.
    if (auto* q = cached("SELECT 1 FROM quotas WHERE fingerprint=?1"
                         " UNION ALL SELECT 1 FROM rentals"
                         " WHERE fingerprint=?1 AND state='active' AND paid_until>?2 LIMIT 1")) {
        q->text(1, fingerprint).i64(2, util::now_unix());
        const bool exempt = q->step() == SQLITE_ROW;
        q->reset();
        if (exempt) return false;
    }

    if (free_tier_bytes_locked() + add_bytes > common_pool_bytes_) return true;
    // Bump the running estimate so back-to-back stores between refreshes
    // cannot slide past the cap.
    free_tier_memo_ += add_bytes;
    return false;
}

std::int64_t Db::free_tier_used_bytes() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;
    return free_tier_bytes_locked();
}

bool Db::exec(const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        log::error("sqlite exec failed: ", err ? err : "?", " | ", sql);
        sqlite3_free(err);
        return false;
    }
    return true;
}

Db::Stmt* Db::cached(const char* sql) {
    auto it = stmts_.find(sql);
    if (it == stmts_.end()) {
        auto st = std::make_unique<Stmt>(db_, sql);
        if (!*st) return nullptr;
        it = stmts_.emplace(sql, std::move(st)).first;
    }
    it->second->reset();
    return it->second.get();
}

bool Db::migrate() {
    if (!exec(
            "CREATE TABLE IF NOT EXISTS drops("
            "  id         TEXT PRIMARY KEY,"
            "  recipient  TEXT NOT NULL,"
            "  from_hint  TEXT NOT NULL DEFAULT '',"
            "  payload    BLOB NOT NULL,"
            "  created_at INTEGER NOT NULL,"
            "  expires_at INTEGER NOT NULL"
            ")"))  // rowid table: payloads are too large for WITHOUT ROWID
        return false;
    if (!exec("CREATE INDEX IF NOT EXISTS idx_drops_recipient ON drops(recipient, created_at)"))
        return false;
    if (!exec("CREATE INDEX IF NOT EXISTS idx_drops_expiry ON drops(expires_at)")) return false;

    if (!exec(
            "CREATE TABLE IF NOT EXISTS invites("
            "  code       TEXT PRIMARY KEY,"
            "  created_at INTEGER NOT NULL,"
            "  issued_by  TEXT NOT NULL DEFAULT '',"
            "  burned_at  INTEGER,"
            "  burned_by  TEXT"
            ") WITHOUT ROWID"))
        return false;
    if (!exec("CREATE INDEX IF NOT EXISTS idx_invites_open ON invites(burned_at)")) return false;

    if (!exec(
            "CREATE TABLE IF NOT EXISTS identities("
            "  fingerprint   TEXT PRIMARY KEY,"
            "  home_relay    TEXT NOT NULL,"
            "  pubkey        TEXT NOT NULL DEFAULT '',"
            "  registered_at INTEGER NOT NULL,"
            "  last_seen     INTEGER NOT NULL"
            ") WITHOUT ROWID"))
        return false;

    if (!exec("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID"))
        return false;

    if (!exec(
            "CREATE TABLE IF NOT EXISTS journal("
            "  fingerprint TEXT NOT NULL,"
            "  seq         INTEGER NOT NULL,"
            "  data        BLOB NOT NULL,"
            "  created_at  INTEGER NOT NULL,"
            "  PRIMARY KEY(fingerprint, seq)"
            ")"))
        return false;

    if (!exec(
            "CREATE TABLE IF NOT EXISTS blobs("
            "  id         TEXT NOT NULL,"   // sha256 of the content, hex
            "  owner      TEXT NOT NULL,"
            "  size       INTEGER NOT NULL,"
            "  created_at INTEGER NOT NULL,"
            "  expires_at INTEGER NOT NULL,"
            "  PRIMARY KEY(id, owner)"
            ") WITHOUT ROWID"))
        return false;
    if (!exec("CREATE INDEX IF NOT EXISTS idx_blobs_owner ON blobs(owner)")) return false;
    if (!exec("CREATE INDEX IF NOT EXISTS idx_blobs_expiry ON blobs(expires_at)")) return false;

    if (!exec(
            "CREATE TABLE IF NOT EXISTS owners("
            "  fingerprint TEXT PRIMARY KEY,"
            "  added_at    INTEGER NOT NULL"
            ") WITHOUT ROWID"))
        return false;

    // Only users whose allowance was changed appear here; everyone else uses
    // the relay-wide default, so the table stays small however many identities
    // register.
    if (!exec(
            "CREATE TABLE IF NOT EXISTS quotas("
            "  fingerprint TEXT PRIMARY KEY,"
            "  max_bytes   INTEGER NOT NULL,"
            "  updated_at  INTEGER NOT NULL"
            ") WITHOUT ROWID"))
        return false;

    // ---- v2: invite lineage, revocation and doorway columns ----------------
    // Column presence is checked directly rather than trusting user_version,
    // so a migration interrupted halfway resumes cleanly on the next start.
    auto column_missing = [&](const char* table, const char* column) {
        auto* st = cached("SELECT 1 FROM pragma_table_info(?1) WHERE name=?2");
        if (!st) return false;
        st->text(1, table).text(2, column);
        const bool present = st->step() == SQLITE_ROW;
        st->reset();
        return !present;
    };
    static const char* kInviteV2Columns[][2] = {
        {"revoked_at", "ALTER TABLE invites ADD COLUMN revoked_at INTEGER"},
        {"revoked_by", "ALTER TABLE invites ADD COLUMN revoked_by TEXT"},
        {"parent_code", "ALTER TABLE invites ADD COLUMN parent_code TEXT"},
        {"contact_token", "ALTER TABLE invites ADD COLUMN contact_token TEXT"},
    };
    for (const auto& col : kInviteV2Columns)
        if (column_missing("invites", col[0]) && !exec(col[1])) return false;

    if (!exec("CREATE INDEX IF NOT EXISTS idx_invites_parent ON invites(parent_code)"))
        return false;
    if (!exec("CREATE INDEX IF NOT EXISTS idx_invites_token ON invites(contact_token)"))
        return false;

    // Setup cards handed out by the redeem page: the relay stores only the
    // SHA-256 of the card key, never the key itself.
    if (!exec(
            "CREATE TABLE IF NOT EXISTS cards("
            "  card_key_hash TEXT PRIMARY KEY,"
            "  invite_code   TEXT NOT NULL,"
            "  created_at    INTEGER NOT NULL"
            ") WITHOUT ROWID"))
        return false;

    // Per-account retention overrides, like quotas: only the exceptions are
    // stored. -1 means keep forever (in practice a century).
    if (!exec(
            "CREATE TABLE IF NOT EXISTS account_ttls("
            "  fingerprint TEXT PRIMARY KEY,"
            "  ttl_days    INTEGER NOT NULL,"
            "  updated_at  INTEGER NOT NULL"
            ") WITHOUT ROWID"))
        return false;

    // Mail pointers: signed statements that some other relay holds payloads
    // for an identity. Held here because this relay homes that identity, is
    // one of its rendezvous relays, or saw it connect.
    if (!exec(
            "CREATE TABLE IF NOT EXISTS pointers("
            "  fingerprint TEXT NOT NULL,"
            "  address     TEXT NOT NULL,"
            "  count       INTEGER NOT NULL,"
            "  node_id     TEXT NOT NULL,"
            "  ed25519     TEXT NOT NULL,"
            "  sig         TEXT NOT NULL,"
            "  created_at  INTEGER NOT NULL,"
            "  expires_at  INTEGER NOT NULL,"
            "  PRIMARY KEY(fingerprint, address)"
            ") WITHOUT ROWID"))
        return false;
    if (!exec("CREATE INDEX IF NOT EXISTS idx_pointers_expiry ON pointers(expires_at)"))
        return false;

    // Collection authorizations are single use: the nonce is burned when
    // presented, and a replayed instruction is refused.
    if (!exec(
            "CREATE TABLE IF NOT EXISTS used_authz("
            "  nonce      TEXT PRIMARY KEY,"
            "  created_at INTEGER NOT NULL"
            ") WITHOUT ROWID"))
        return false;

    // ---- v4: client x25519 keys -------------------------------------------
    // Wallets register a curve25519 public key alongside ed25519 (sent on
    // hello and invite_claim). Stored so pointer contents can later be sealed
    // to the recipient. Never required; empty for pre-v4 identities.
    if (column_missing("identities", "x25519") &&
        !exec("ALTER TABLE identities ADD COLUMN x25519 TEXT NOT NULL DEFAULT ''"))
        return false;

    // ---- v5: invite activation --------------------------------------------
    // A member's codes start locked and unlock once the member has received
    // real traffic and (when invited by an identity) been vouched for.
    if (column_missing("invites", "locked") &&
        !exec("ALTER TABLE invites ADD COLUMN locked INTEGER NOT NULL DEFAULT 0"))
        return false;
    if (column_missing("identities", "received") &&
        !exec("ALTER TABLE identities ADD COLUMN received INTEGER NOT NULL DEFAULT 0"))
        return false;
    if (column_missing("identities", "vouched_at") &&
        !exec("ALTER TABLE identities ADD COLUMN vouched_at INTEGER"))
        return false;
    if (!exec("CREATE INDEX IF NOT EXISTS idx_invites_burned_by ON invites(burned_by)"))
        return false;
    if (!exec("CREATE INDEX IF NOT EXISTS idx_invites_issued_by ON invites(issued_by)"))
        return false;

    // ---- v3: storage market -----------------------------------------------
    // Rentals are reservations against the market pool; their bytes act as
    // extra allowance while paid. Vouchers are the wallet-signed settlement
    // statements, stored verbatim -- the chain contract verifies them, the
    // relay never does.
    if (!exec(
            "CREATE TABLE IF NOT EXISTS rentals("
            "  id          TEXT PRIMARY KEY,"
            "  fingerprint TEXT NOT NULL,"
            "  bytes       INTEGER NOT NULL,"
            "  price_micro INTEGER NOT NULL,"
            "  payment_key TEXT NOT NULL DEFAULT '',"
            "  created_at  INTEGER NOT NULL,"
            "  paid_until  INTEGER NOT NULL,"
            "  state       TEXT NOT NULL DEFAULT 'active'"
            ") WITHOUT ROWID"))
        return false;
    if (!exec("CREATE INDEX IF NOT EXISTS idx_rentals_fp ON rentals(fingerprint)")) return false;

    if (!exec(
            "CREATE TABLE IF NOT EXISTS vouchers("
            "  payment_key      TEXT NOT NULL,"
            "  payout           TEXT NOT NULL,"
            "  cumulative_micro INTEGER NOT NULL,"
            "  sig              TEXT NOT NULL,"
            "  raw              TEXT NOT NULL,"
            "  created_at       INTEGER NOT NULL,"
            "  PRIMARY KEY(payment_key, payout, cumulative_micro)"
            ")"))
        return false;

    char buf[64];
    std::snprintf(buf, sizeof buf, "PRAGMA user_version=%d", kSchemaVersion);
    exec(buf);
    return true;
}

// ------------------------------------------------------------- drops -------

Db::StoreResult Db::store_drop(const std::string& id, const std::string& recipient,
                               const void* payload, std::size_t len, const std::string& from_hint,
                               std::int64_t created_at, std::int64_t expires_at,
                               std::int64_t* out_seq) {
    if (out_seq) *out_seq = 0;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return StoreResult::error;

    // An individual allowance overrides the relay default; rented bytes add
    // on top.
    const std::int64_t allowance = allowance_locked(recipient);

    if (auto* q = cached("SELECT COUNT(*), IFNULL(SUM(LENGTH(payload)),0) FROM drops "
                         "WHERE recipient=?1 AND expires_at>?2")) {
        q->text(1, recipient).i64(2, created_at);
        if (q->step() == SQLITE_ROW) {
            const std::int64_t count = q->col_i64(0);
            const std::int64_t bytes = q->col_i64(1);
            q->reset();
            if (count >= max_drops_per_recipient_ ||
                bytes + static_cast<std::int64_t>(len) > allowance)
                return StoreResult::quota_exceeded;
        } else {
            q->reset();
        }
    }
    if (common_pool_exceeded(recipient, static_cast<std::int64_t>(len)))
        return StoreResult::quota_exceeded;

    auto* st = cached("INSERT OR IGNORE INTO drops"
                      "(id, recipient, from_hint, payload, created_at, expires_at)"
                      " VALUES(?1,?2,?3,?4,?5,?6)");
    if (!st) return StoreResult::error;
    st->text(1, id).text(2, recipient).text(3, from_hint).blob(4, payload, len).i64(5, created_at)
       .i64(6, expires_at);
    const int rc = st->step();
    const int changes = sqlite3_changes(db_);
    if (out_seq && rc == SQLITE_DONE && changes > 0)
        *out_seq = sqlite3_last_insert_rowid(db_);
    st->reset();
    if (rc != SQLITE_DONE) {
        log::error("store_drop failed: ", sqlite3_errmsg(db_));
        return StoreResult::error;
    }
    return changes > 0 ? StoreResult::ok : StoreResult::duplicate;
}

std::vector<Db::Drop> Db::fetch_drops(const std::string& recipient, std::int64_t after_seq,
                                      int limit) {
    std::vector<Drop> out;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return out;

    auto* st = cached("SELECT rowid, id, from_hint, payload, created_at, expires_at FROM drops"
                      " WHERE recipient=?1 AND rowid>?2 AND expires_at>?3"
                      " ORDER BY rowid ASC LIMIT ?4");
    if (!st) return out;
    const std::int64_t now = util::now_unix();
    st->text(1, recipient).i64(2, after_seq).i64(3, now).i64(4, limit);
    while (st->step() == SQLITE_ROW) {
        Drop d;
        d.seq = st->col_i64(0);
        d.id = st->col_text(1);
        d.recipient = recipient;
        d.from_hint = st->col_text(2);
        d.payload = st->col_blob(3);
        d.created_at = st->col_i64(4);
        d.expires_at = st->col_i64(5);
        out.push_back(std::move(d));
    }
    st->reset();
    return out;
}

int Db::ack_drops(const std::string& recipient, const std::vector<std::string>& ids) {
    if (ids.empty()) return 0;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;

    int removed = 0;
    exec("BEGIN IMMEDIATE");
    auto* st = cached("DELETE FROM drops WHERE recipient=?1 AND id=?2");
    if (st) {
        for (const auto& id : ids) {
            st->reset().text(1, recipient).text(2, id);
            if (st->step() == SQLITE_DONE) removed += sqlite3_changes(db_);
        }
        st->reset();
    }
    exec("COMMIT");
    return removed;
}

std::int64_t Db::pending_for(const std::string& recipient) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;
    auto* st = cached("SELECT COUNT(*) FROM drops WHERE recipient=?1 AND expires_at>?2");
    if (!st) return 0;
    st->text(1, recipient).i64(2, util::now_unix());
    std::int64_t n = 0;
    if (st->step() == SQLITE_ROW) n = st->col_i64(0);
    st->reset();
    return n;
}

int Db::prune_expired(std::int64_t now) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;
    auto* st = cached("DELETE FROM drops WHERE expires_at<=?1");
    if (!st) return 0;
    st->i64(1, now);
    const int rc = st->step();
    const int removed = (rc == SQLITE_DONE) ? sqlite3_changes(db_) : 0;
    st->reset();
    return removed;
}

// ------------------------------------------------------------ journal ------

Db::AppendResult Db::journal_append(const std::string& fingerprint, const void* data,
                                    std::size_t len, std::int64_t& out_seq) {
    out_seq = 0;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return AppendResult::error;

    const std::int64_t allowance = allowance_locked(fingerprint);

    if (!exec("BEGIN IMMEDIATE")) return AppendResult::error;

    // Everything an identity stores counts against one allowance: waiting
    // messages, its journal, and its voice and video.
    std::int64_t used = 0;
    if (auto* q = cached("SELECT"
                         " (SELECT IFNULL(SUM(LENGTH(payload)),0) FROM drops WHERE recipient=?1)"
                         "+(SELECT IFNULL(SUM(LENGTH(data)),0) FROM journal WHERE fingerprint=?1)"
                         "+(SELECT IFNULL(SUM(size),0) FROM blobs WHERE owner=?1)")) {
        q->text(1, fingerprint);
        if (q->step() == SQLITE_ROW) used = q->col_i64(0);
        q->reset();
    }
    if (used + static_cast<std::int64_t>(len) > allowance) {
        exec("ROLLBACK");
        return AppendResult::quota_exceeded;
    }
    if (common_pool_exceeded(fingerprint, static_cast<std::int64_t>(len))) {
        exec("ROLLBACK");
        return AppendResult::quota_exceeded;
    }

    std::int64_t seq = 1;
    if (auto* q = cached("SELECT IFNULL(MAX(seq),0)+1 FROM journal WHERE fingerprint=?1")) {
        q->text(1, fingerprint);
        if (q->step() == SQLITE_ROW) seq = q->col_i64(0);
        q->reset();
    }

    auto* st = cached("INSERT INTO journal(fingerprint, seq, data, created_at)"
                      " VALUES(?1,?2,?3,?4)");
    if (!st) {
        exec("ROLLBACK");
        return AppendResult::error;
    }
    st->text(1, fingerprint).i64(2, seq).blob(3, data, len).i64(4, util::now_unix());
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    if (!ok) {
        exec("ROLLBACK");
        return AppendResult::error;
    }
    exec("COMMIT");
    out_seq = seq;
    return AppendResult::ok;
}

std::vector<Db::JournalEntry> Db::journal_read(const std::string& fingerprint,
                                               std::int64_t after_seq, int limit,
                                               std::size_t max_bytes, bool* truncated) {
    std::vector<JournalEntry> out;
    if (truncated) *truncated = false;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return out;
    auto* st = cached("SELECT seq, data, created_at FROM journal"
                      " WHERE fingerprint=?1 AND seq>?2 ORDER BY seq ASC LIMIT ?3");
    if (!st) return out;
    st->text(1, fingerprint).i64(2, after_seq).i64(3, limit);
    std::size_t total = 0;
    while (st->step() == SQLITE_ROW) {
        JournalEntry e;
        e.seq = st->col_i64(0);
        e.data = st->col_blob(1);
        e.created_at = st->col_i64(2);
        // Stop on the entry that would take the reply over the cap, so a
        // client with a long history pages through instead of being cut off.
        if (!out.empty() && total + e.data.size() > max_bytes) {
            if (truncated) *truncated = true;
            break;
        }
        total += e.data.size();
        out.push_back(std::move(e));
    }
    st->reset();
    return out;
}

// -------------------------------------------------------------- blobs ------

Db::BlobResult Db::blob_record(const std::string& id, const std::string& owner, std::int64_t size,
                               std::int64_t expires_at) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return BlobResult::error;

    const std::int64_t allowance = allowance_locked(owner);

    if (auto* q = cached("SELECT 1 FROM blobs WHERE id=?1 AND owner=?2")) {
        q->text(1, id).text(2, owner);
        const bool already = q->step() == SQLITE_ROW;
        q->reset();
        if (already) return BlobResult::duplicate;
    }

    std::int64_t used = 0;
    if (auto* q = cached("SELECT"
                         " (SELECT IFNULL(SUM(LENGTH(payload)),0) FROM drops WHERE recipient=?1)"
                         "+(SELECT IFNULL(SUM(LENGTH(data)),0) FROM journal WHERE fingerprint=?1)"
                         "+(SELECT IFNULL(SUM(size),0) FROM blobs WHERE owner=?1)")) {
        q->text(1, owner);
        if (q->step() == SQLITE_ROW) used = q->col_i64(0);
        q->reset();
    }
    if (used + size > allowance) return BlobResult::quota_exceeded;
    if (common_pool_exceeded(owner, size)) return BlobResult::quota_exceeded;

    auto* st = cached("INSERT INTO blobs(id, owner, size, created_at, expires_at)"
                      " VALUES(?1,?2,?3,?4,?5)");
    if (!st) return BlobResult::error;
    st->text(1, id).text(2, owner).i64(3, size).i64(4, util::now_unix()).i64(5, expires_at);
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok ? BlobResult::ok : BlobResult::error;
}

bool Db::blob_exists(const std::string& id) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("SELECT 1 FROM blobs WHERE id=?1 AND expires_at>?2 LIMIT 1");
    if (!st) return false;
    st->text(1, id).i64(2, util::now_unix());
    const bool found = st->step() == SQLITE_ROW;
    st->reset();
    return found;
}

std::int64_t Db::blob_size(const std::string& id) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;
    auto* st = cached("SELECT size FROM blobs WHERE id=?1 LIMIT 1");
    if (!st) return 0;
    st->text(1, id);
    std::int64_t n = 0;
    if (st->step() == SQLITE_ROW) n = st->col_i64(0);
    st->reset();
    return n;
}

std::vector<std::string> Db::prune_blobs(std::int64_t now) {
    std::vector<std::string> orphaned;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return orphaned;

    exec("BEGIN IMMEDIATE");

    // Note which blobs are losing a reference before the rows disappear.
    std::vector<std::string> candidates;
    if (auto* st = cached("SELECT DISTINCT id FROM blobs WHERE expires_at<=?1")) {
        st->i64(1, now);
        while (st->step() == SQLITE_ROW) candidates.push_back(st->col_text(0));
        st->reset();
    }

    if (auto* st = cached("DELETE FROM blobs WHERE expires_at<=?1")) {
        st->i64(1, now);
        st->step();
        st->reset();
    }

    // The bytes survive while any owner still references them, so only the
    // ids with no rows left are safe to delete from disk.
    if (auto* st = cached("SELECT 1 FROM blobs WHERE id=?1 LIMIT 1")) {
        for (const auto& id : candidates) {
            st->reset().text(1, id);
            if (st->step() != SQLITE_ROW) orphaned.push_back(id);
        }
        st->reset();
    }

    exec("COMMIT");
    return orphaned;
}

std::int64_t Db::count_blobs() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;
    auto* st = cached("SELECT COUNT(DISTINCT id) FROM blobs");
    if (!st) return 0;
    std::int64_t n = 0;
    if (st->step() == SQLITE_ROW) n = st->col_i64(0);
    st->reset();
    return n;
}

// ------------------------------------------------------- relay owners ------

bool Db::owner_add(const std::string& fingerprint) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("INSERT INTO owners(fingerprint, added_at) VALUES(?1,?2)"
                      " ON CONFLICT(fingerprint) DO NOTHING");
    if (!st) return false;
    st->text(1, fingerprint).i64(2, util::now_unix());
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok;
}

bool Db::owner_remove(const std::string& fingerprint) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("DELETE FROM owners WHERE fingerprint=?1");
    if (!st) return false;
    st->text(1, fingerprint);
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok;
}

bool Db::owner_is(const std::string& fingerprint) {
    if (fingerprint.empty()) return false;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("SELECT 1 FROM owners WHERE fingerprint=?1");
    if (!st) return false;
    st->text(1, fingerprint);
    const bool found = st->step() == SQLITE_ROW;
    st->reset();
    return found;
}

std::vector<std::string> Db::owner_list() {
    std::vector<std::string> out;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return out;
    auto* st = cached("SELECT fingerprint FROM owners ORDER BY added_at");
    if (!st) return out;
    while (st->step() == SQLITE_ROW) out.push_back(st->col_text(0));
    st->reset();
    return out;
}

std::int64_t Db::owner_count() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;
    auto* st = cached("SELECT COUNT(*) FROM owners");
    if (!st) return 0;
    std::int64_t n = 0;
    if (st->step() == SQLITE_ROW) n = st->col_i64(0);
    st->reset();
    return n;
}

std::vector<Db::Account> Db::list_accounts(int limit, int offset) {
    std::vector<Account> out;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return out;

    // One pass: identity, its allowance if it has a custom one, and everything
    // it is currently storing across messages, journal and blobs.
    auto* st = cached(
        "SELECT i.fingerprint, i.home_relay, i.registered_at, i.last_seen,"
        " (SELECT max_bytes FROM quotas q WHERE q.fingerprint=i.fingerprint),"
        " (SELECT IFNULL(SUM(LENGTH(payload)),0) FROM drops WHERE recipient=i.fingerprint)"
        "+(SELECT IFNULL(SUM(LENGTH(data)),0) FROM journal WHERE fingerprint=i.fingerprint)"
        "+(SELECT IFNULL(SUM(size),0) FROM blobs WHERE owner=i.fingerprint)"
        " FROM identities i ORDER BY i.last_seen DESC LIMIT ?1 OFFSET ?2");
    if (!st) return out;
    st->i64(1, limit).i64(2, offset);
    while (st->step() == SQLITE_ROW) {
        Account a;
        a.fingerprint = st->col_text(0);
        a.home_relay = st->col_text(1);
        a.registered_at = st->col_i64(2);
        a.last_seen = st->col_i64(3);
        const bool custom = sqlite3_column_type(st->raw(), 4) != SQLITE_NULL;
        a.custom_quota = custom;
        a.quota_bytes = custom ? st->col_i64(4) : max_bytes_per_recipient_;
        a.used_bytes = st->col_i64(5);
        out.push_back(std::move(a));
    }
    st->reset();
    return out;
}

// ------------------------------------------------------------- quotas ------

Db::Quota Db::quota_for(const std::string& fingerprint) {
    Quota q;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return q;

    q.max_bytes = max_bytes_per_recipient_;
    q.max_drops = max_drops_per_recipient_;

    if (auto* st = cached("SELECT max_bytes FROM quotas WHERE fingerprint=?1")) {
        st->text(1, fingerprint);
        if (st->step() == SQLITE_ROW) {
            q.max_bytes = st->col_i64(0);
            q.custom = true;
        }
        st->reset();
    }
    // Paid rentals raise the allowance for as long as they are paid.
    if (auto* st = cached("SELECT IFNULL(SUM(bytes),0) FROM rentals"
                          " WHERE fingerprint=?1 AND state='active' AND paid_until>?2")) {
        st->text(1, fingerprint).i64(2, util::now_unix());
        if (st->step() == SQLITE_ROW) q.max_bytes += st->col_i64(0);
        st->reset();
    }
    if (auto* st = cached("SELECT COUNT(*), IFNULL(SUM(LENGTH(payload)),0) FROM drops"
                          " WHERE recipient=?1 AND expires_at>?2")) {
        st->text(1, fingerprint).i64(2, util::now_unix());
        if (st->step() == SQLITE_ROW) {
            q.used_drops = st->col_i64(0);
            q.used_bytes = st->col_i64(1);
        }
        st->reset();
    }
    // Waiting messages are only part of it: the journal and any voice or video
    // this identity uploaded count against the same allowance.
    if (auto* st = cached("SELECT"
                          " (SELECT IFNULL(SUM(LENGTH(data)),0) FROM journal WHERE fingerprint=?1)"
                          "+(SELECT IFNULL(SUM(size),0) FROM blobs WHERE owner=?1)")) {
        st->text(1, fingerprint);
        if (st->step() == SQLITE_ROW) q.used_bytes += st->col_i64(0);
        st->reset();
    }
    return q;
}

bool Db::set_quota_bytes(const std::string& fingerprint, std::int64_t max_bytes) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("INSERT INTO quotas(fingerprint, max_bytes, updated_at) VALUES(?1,?2,?3)"
                      " ON CONFLICT(fingerprint) DO UPDATE SET"
                      "  max_bytes=excluded.max_bytes, updated_at=excluded.updated_at");
    if (!st) return false;
    st->text(1, fingerprint).i64(2, max_bytes).i64(3, util::now_unix());
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok;
}

bool Db::clear_quota(const std::string& fingerprint) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("DELETE FROM quotas WHERE fingerprint=?1");
    if (!st) return false;
    st->text(1, fingerprint);
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok;
}

std::vector<std::pair<std::string, std::int64_t>> Db::list_quotas() {
    std::vector<std::pair<std::string, std::int64_t>> out;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return out;
    auto* st = cached("SELECT fingerprint, max_bytes FROM quotas ORDER BY fingerprint");
    if (!st) return out;
    while (st->step() == SQLITE_ROW) out.emplace_back(st->col_text(0), st->col_i64(1));
    st->reset();
    return out;
}

// ------------------------------------------------------------ invites ------

bool Db::invite_is_open(const std::string& code) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("SELECT burned_at, revoked_at, locked FROM invites WHERE code=?1");
    if (!st) return false;
    st->text(1, code);
    bool open = false;
    if (st->step() == SQLITE_ROW)
        open = sqlite3_column_type(st->raw(), 0) == SQLITE_NULL &&
               sqlite3_column_type(st->raw(), 1) == SQLITE_NULL && st->col_i64(2) == 0;
    st->reset();
    return open;
}

Db::ClaimResult Db::claim_invite(const std::string& code, const std::string& fingerprint,
                                 const std::string& home_relay, const std::string& pubkey,
                                 int new_code_count, const std::string& hint_hex,
                                 std::vector<std::string>& out_codes) {
    out_codes.clear();
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return ClaimResult::error;

    if (!exec("BEGIN IMMEDIATE")) return ClaimResult::error;
    auto rollback = [&](ClaimResult r) {
        exec("ROLLBACK");
        return r;
    };

    // Does the code exist at all?
    {
        auto* q = cached("SELECT burned_at, revoked_at, locked FROM invites WHERE code=?1");
        if (!q) return rollback(ClaimResult::error);
        q->text(1, code);
        const int rc = q->step();
        if (rc != SQLITE_ROW) {
            q->reset();
            return rollback(ClaimResult::not_found);
        }
        const bool already = sqlite3_column_type(q->raw(), 0) != SQLITE_NULL;
        const bool revoked = sqlite3_column_type(q->raw(), 1) != SQLITE_NULL;
        const bool locked = q->col_i64(2) != 0;
        q->reset();
        if (revoked) return rollback(ClaimResult::revoked);
        if (already) return rollback(ClaimResult::already_used);
        if (locked) return rollback(ClaimResult::locked);
    }

    // One registration per identity. Without this a member could claim their
    // own codes and mint three more each time; a second claim needs a new key.
    {
        auto* q = cached("SELECT 1 FROM identities WHERE fingerprint=?1");
        if (!q) return rollback(ClaimResult::error);
        q->text(1, fingerprint);
        const bool exists = q->step() == SQLITE_ROW;
        q->reset();
        if (exists) return rollback(ClaimResult::already_registered);
    }

    const std::int64_t now = util::now_unix();

    // Burn it. The WHERE clause makes this the atomic winner-takes-all step.
    {
        auto* st = cached("UPDATE invites SET burned_at=?1, burned_by=?2"
                          " WHERE code=?3 AND burned_at IS NULL AND revoked_at IS NULL"
                          " AND locked=0");
        if (!st) return rollback(ClaimResult::error);
        st->i64(1, now).text(2, fingerprint).text(3, code);
        if (st->step() != SQLITE_DONE) {
            st->reset();
            return rollback(ClaimResult::error);
        }
        const int changed = sqlite3_changes(db_);
        st->reset();
        if (changed == 0) return rollback(ClaimResult::already_used);
    }

    // Record where this identity keeps its mail.
    {
        auto* st = cached("INSERT INTO identities"
                          "(fingerprint, home_relay, pubkey, registered_at, last_seen)"
                          " VALUES(?1,?2,?3,?4,?4)"
                          " ON CONFLICT(fingerprint) DO UPDATE SET"
                          "  home_relay=excluded.home_relay,"
                          "  pubkey=CASE WHEN excluded.pubkey<>'' THEN excluded.pubkey"
                          "              ELSE identities.pubkey END,"
                          "  last_seen=excluded.last_seen");
        if (!st) return rollback(ClaimResult::error);
        st->text(1, fingerprint).text(2, home_relay).text(3, pubkey).i64(4, now);
        if (st->step() != SQLITE_DONE) {
            st->reset();
            return rollback(ClaimResult::error);
        }
        st->reset();
    }

    // Hand out the next generation of codes, linked to the claimed one so the
    // revoke cascade can walk the tree later.
    {
        auto* st = cached(
            "INSERT INTO invites(code, created_at, issued_by, parent_code, contact_token, locked)"
            " VALUES(?1,?2,?3,?4,?5,1)");
        if (!st) return rollback(ClaimResult::error);
        for (int i = 0; i < new_code_count; ++i) {
            const std::string fresh = crypto::invite_code(hint_hex);
            const std::string token = util::hex_encode(crypto::random_bytes(16));
            st->reset().text(1, fresh).i64(2, now).text(3, fingerprint).text(4, code)
               .text(5, token);
            if (st->step() != SQLITE_DONE) {
                st->reset();
                out_codes.clear();
                return rollback(ClaimResult::error);
            }
            out_codes.push_back(fresh);
        }
        st->reset();
    }

    if (!exec("COMMIT")) {
        out_codes.clear();
        return rollback(ClaimResult::error);
    }
    return ClaimResult::ok;
}

std::vector<std::string> Db::mint_invites(int n, const std::string& issued_by,
                                          const std::string& hint_hex,
                                          const std::string& parent_code, bool locked) {
    std::vector<std::string> out;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return out;
    auto* st = cached(
        "INSERT INTO invites(code, created_at, issued_by, parent_code, contact_token, locked)"
        " VALUES(?1,?2,?3,?4,?5,?6)");
    if (!st) return out;
    // A contact token only makes sense when a real identity minted the code:
    // /m/<token> resolves to that identity's public key.
    const bool with_token = util::is_valid_fingerprint(issued_by);
    const std::int64_t now = util::now_unix();
    exec("BEGIN IMMEDIATE");
    for (int i = 0; i < n; ++i) {
        const std::string code = crypto::invite_code(hint_hex);
        st->reset().text(1, code).i64(2, now).text(3, issued_by);
        if (parent_code.empty()) st->null(4); else st->text(4, parent_code);
        if (with_token) st->text(5, util::hex_encode(crypto::random_bytes(16)));
        else st->null(5);
        st->i64(6, locked ? 1 : 0);
        if (st->step() == SQLITE_DONE) out.push_back(code);
    }
    st->reset();
    exec("COMMIT");
    return out;
}

Db::RevokeResult Db::revoke_invite(const std::string& code, bool cascade,
                                   const std::string& revoked_by) {
    RevokeResult r;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return r;

    if (!exec("BEGIN IMMEDIATE")) return r;

    {
        auto* q = cached("SELECT 1 FROM invites WHERE code=?1");
        if (!q) { exec("ROLLBACK"); return r; }
        q->text(1, code);
        r.found = q->step() == SQLITE_ROW;
        q->reset();
        if (!r.found) {
            exec("ROLLBACK");
            return r;
        }
    }

    const std::int64_t now = util::now_unix();
    auto* mark = cached("UPDATE invites SET revoked_at=?1, revoked_by=?2"
                        " WHERE code=?3 AND burned_at IS NULL AND revoked_at IS NULL");
    if (!mark) { exec("ROLLBACK"); return RevokeResult{}; }

    mark->text(2, revoked_by).i64(1, now).text(3, code);
    if (mark->step() == SQLITE_DONE) r.direct = sqlite3_changes(db_);
    mark->reset();

    if (cascade) {
        // Breadth-first over parent_code. Claimed codes stay in the frontier
        // so the whole descendant tree is reached, but only open codes are
        // marked -- identities created from claimed codes are never unbound.
        std::vector<std::string> frontier{code};
        auto* kids = cached("SELECT code FROM invites WHERE parent_code=?1");
        if (!kids) { exec("ROLLBACK"); return RevokeResult{}; }
        while (!frontier.empty()) {
            std::vector<std::string> next;
            for (const auto& parent : frontier) {
                kids->reset().text(1, parent);
                while (kids->step() == SQLITE_ROW) next.push_back(kids->col_text(0));
            }
            kids->reset();
            for (const auto& child : next) {
                mark->reset().text(2, revoked_by).i64(1, now).text(3, child);
                if (mark->step() == SQLITE_DONE) r.cascaded += sqlite3_changes(db_);
            }
            mark->reset();
            frontier = std::move(next);
        }
    }

    exec("COMMIT");
    return r;
}

Db::InviteInfo Db::invite_info(const std::string& code) {
    InviteInfo info;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return info;
    auto* st = cached("SELECT burned_at, revoked_at, issued_by, contact_token, locked"
                      " FROM invites WHERE code=?1");
    if (!st) return info;
    st->text(1, code);
    if (st->step() == SQLITE_ROW) {
        info.found = true;
        info.burned = sqlite3_column_type(st->raw(), 0) != SQLITE_NULL;
        info.revoked = sqlite3_column_type(st->raw(), 1) != SQLITE_NULL;
        info.issued_by = st->col_text(2);
        info.contact_token = st->col_text(3);
        info.locked = st->col_i64(4) != 0;
    }
    st->reset();
    return info;
}

Db::CardRedeemResult Db::redeem_for_card(const std::string& code,
                                         const std::string& card_key_hash) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return CardRedeemResult::error;
    if (!exec("BEGIN IMMEDIATE")) return CardRedeemResult::error;

    const std::int64_t now = util::now_unix();
    {
        // A web redemption has no identity yet; the burner is the card itself.
        auto* st = cached("UPDATE invites SET burned_at=?1, burned_by=?2"
                          " WHERE code=?3 AND burned_at IS NULL AND revoked_at IS NULL AND locked=0");
        if (!st) { exec("ROLLBACK"); return CardRedeemResult::error; }
        st->i64(1, now).text(2, "card:" + card_key_hash.substr(0, 16)).text(3, code);
        const bool done = st->step() == SQLITE_DONE;
        const int changed = done ? sqlite3_changes(db_) : 0;
        st->reset();
        if (!done) { exec("ROLLBACK"); return CardRedeemResult::error; }
        if (changed == 0) { exec("ROLLBACK"); return CardRedeemResult::race; }
    }
    {
        auto* st = cached("INSERT INTO cards(card_key_hash, invite_code, created_at)"
                          " VALUES(?1,?2,?3)");
        if (!st) { exec("ROLLBACK"); return CardRedeemResult::error; }
        st->text(1, card_key_hash).text(2, code).i64(3, now);
        const bool ok = st->step() == SQLITE_DONE;
        st->reset();
        if (!ok) { exec("ROLLBACK"); return CardRedeemResult::error; }
    }
    if (!exec("COMMIT")) { exec("ROLLBACK"); return CardRedeemResult::error; }
    return CardRedeemResult::ok;
}

Db::ContactInfo Db::contact_info(const std::string& token) {
    ContactInfo info;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return info;
    auto* st = cached("SELECT i.issued_by, i.revoked_at, IFNULL(id.pubkey,'')"
                      " FROM invites i LEFT JOIN identities id ON id.fingerprint=i.issued_by"
                      " WHERE i.contact_token=?1 LIMIT 1");
    if (!st) return info;
    st->text(1, token);
    if (st->step() == SQLITE_ROW) {
        info.found = true;
        info.fingerprint = st->col_text(0);
        info.revoked = sqlite3_column_type(st->raw(), 1) != SQLITE_NULL;
        info.pubkey_b64 = st->col_text(2);
    }
    st->reset();
    return info;
}

// ------------------------------------------------------ mail pointers ------

bool Db::pointer_store(const std::string& fingerprint, const std::string& address,
                       std::int64_t count, const std::string& node_id,
                       const std::string& ed25519_b64, const std::string& sig_b64,
                       std::int64_t created_at, std::int64_t expires_at) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached(
        "INSERT INTO pointers(fingerprint, address, count, node_id, ed25519, sig,"
        " created_at, expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)"
        " ON CONFLICT(fingerprint, address) DO UPDATE SET"
        "  count=excluded.count, node_id=excluded.node_id, ed25519=excluded.ed25519,"
        "  sig=excluded.sig, created_at=excluded.created_at, expires_at=excluded.expires_at"
        " WHERE excluded.created_at >= pointers.created_at");
    if (!st) return false;
    st->text(1, fingerprint).text(2, address).i64(3, count).text(4, node_id)
       .text(5, ed25519_b64).text(6, sig_b64).i64(7, created_at).i64(8, expires_at);
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok;
}

std::vector<Db::Pointer> Db::pointers_for(const std::string& fingerprint) {
    std::vector<Pointer> out;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return out;
    auto* st = cached("SELECT address, count, created_at FROM pointers"
                      " WHERE fingerprint=?1 AND expires_at>?2 ORDER BY created_at DESC");
    if (!st) return out;
    st->text(1, fingerprint).i64(2, util::now_unix());
    while (st->step() == SQLITE_ROW)
        out.push_back({st->col_text(0), st->col_i64(1), st->col_i64(2)});
    st->reset();
    return out;
}

bool Db::pointer_delete(const std::string& fingerprint, const std::string& address) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("DELETE FROM pointers WHERE fingerprint=?1 AND address=?2");
    if (!st) return false;
    st->text(1, fingerprint).text(2, address);
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok;
}

bool Db::authz_burn(const std::string& nonce) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("INSERT INTO used_authz(nonce, created_at) VALUES(?1,?2)"
                      " ON CONFLICT(nonce) DO NOTHING");
    if (!st) return false;
    st->text(1, nonce).i64(2, util::now_unix());
    const bool done = st->step() == SQLITE_DONE;
    const int changes = done ? sqlite3_changes(db_) : 0;
    st->reset();
    return done && changes > 0;  // false: already burned (or error)
}

int Db::prune_authz(std::int64_t before) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;
    auto* st = cached("DELETE FROM used_authz WHERE created_at<?1");
    if (!st) return 0;
    st->i64(1, before);
    const int removed = st->step() == SQLITE_DONE ? sqlite3_changes(db_) : 0;
    st->reset();
    return removed;
}

int Db::delete_drops(const std::string& recipient, const std::vector<std::string>& ids) {
    if (ids.empty()) return 0;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;
    int removed = 0;
    exec("BEGIN IMMEDIATE");
    if (auto* st = cached("DELETE FROM drops WHERE recipient=?1 AND id=?2")) {
        for (const auto& id : ids) {
            st->reset().text(1, recipient).text(2, id);
            if (st->step() == SQLITE_DONE) removed += sqlite3_changes(db_);
        }
        st->reset();
    }
    exec("COMMIT");
    return removed;
}

int Db::prune_pointers(std::int64_t now) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;
    auto* st = cached("DELETE FROM pointers WHERE expires_at<=?1");
    if (!st) return 0;
    st->i64(1, now);
    const int removed = st->step() == SQLITE_DONE ? sqlite3_changes(db_) : 0;
    st->reset();
    return removed;
}

// ------------------------------------------------------ admin console ------

std::vector<Db::InviteRow> Db::list_invites(int limit, int offset, const std::string& state) {
    std::vector<InviteRow> out;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return out;

    const char* sql =
        "SELECT code, created_at, issued_by, IFNULL(parent_code,''),"
        " contact_token IS NOT NULL, burned_at, IFNULL(burned_by,''),"
        " revoked_at, IFNULL(revoked_by,''), locked"
        " FROM invites"
        " WHERE (?1='all')"
        "  OR (?1='open'    AND burned_at IS NULL AND revoked_at IS NULL AND locked=0)"
        "  OR (?1='locked'  AND burned_at IS NULL AND revoked_at IS NULL AND locked=1)"
        "  OR (?1='burned'  AND burned_at IS NOT NULL)"
        "  OR (?1='revoked' AND revoked_at IS NOT NULL)"
        " ORDER BY created_at DESC, code LIMIT ?2 OFFSET ?3";
    auto* st = cached(sql);
    if (!st) return out;
    st->text(1, state.empty() ? "all" : state).i64(2, limit).i64(3, offset);
    while (st->step() == SQLITE_ROW) {
        InviteRow r;
        r.code = st->col_text(0);
        r.created_at = st->col_i64(1);
        r.issued_by = st->col_text(2);
        r.parent_code = st->col_text(3);
        r.has_contact_token = st->col_i64(4) != 0;
        const bool burned = sqlite3_column_type(st->raw(), 5) != SQLITE_NULL;
        const bool revoked = sqlite3_column_type(st->raw(), 7) != SQLITE_NULL;
        r.burned_at = st->col_i64(5);
        r.burned_by = st->col_text(6);
        r.revoked_at = st->col_i64(7);
        r.revoked_by = st->col_text(8);
        r.state = revoked ? "revoked" : burned ? "burned" : st->col_i64(9) ? "locked" : "open";
        out.push_back(std::move(r));
    }
    st->reset();
    return out;
}

std::vector<Db::Account> Db::search_accounts(const std::string& q, int limit) {
    std::vector<Account> out;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return out;

    auto* st = cached(
        "SELECT i.fingerprint, i.home_relay, i.registered_at, i.last_seen,"
        " (SELECT max_bytes FROM quotas q WHERE q.fingerprint=i.fingerprint),"
        " (SELECT IFNULL(SUM(LENGTH(payload)),0) FROM drops WHERE recipient=i.fingerprint)"
        "+(SELECT IFNULL(SUM(LENGTH(data)),0) FROM journal WHERE fingerprint=i.fingerprint)"
        "+(SELECT IFNULL(SUM(size),0) FROM blobs WHERE owner=i.fingerprint)"
        " FROM identities i"
        " WHERE i.fingerprint LIKE ?1 || '%' OR instr(i.home_relay, ?1) > 0"
        " ORDER BY i.last_seen DESC LIMIT ?2");
    if (!st) return out;
    st->text(1, q).i64(2, limit);
    while (st->step() == SQLITE_ROW) {
        Account a;
        a.fingerprint = st->col_text(0);
        a.home_relay = st->col_text(1);
        a.registered_at = st->col_i64(2);
        a.last_seen = st->col_i64(3);
        const bool custom = sqlite3_column_type(st->raw(), 4) != SQLITE_NULL;
        a.custom_quota = custom;
        a.quota_bytes = custom ? st->col_i64(4) : max_bytes_per_recipient_;
        a.used_bytes = st->col_i64(5);
        out.push_back(std::move(a));
    }
    st->reset();
    return out;
}

Db::DeleteResult Db::delete_account(const std::string& fingerprint) {
    DeleteResult r;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return r;
    if (!exec("BEGIN IMMEDIATE")) return r;

    // Which blobs might lose their last reference.
    std::vector<std::string> candidates;
    if (auto* st = cached("SELECT DISTINCT id FROM blobs WHERE owner=?1")) {
        st->text(1, fingerprint);
        while (st->step() == SQLITE_ROW) candidates.push_back(st->col_text(0));
        st->reset();
    }

    auto wipe = [&](const char* sql) {
        auto* st = cached(sql);
        if (!st) return -1;
        st->text(1, fingerprint);
        const bool done = st->step() == SQLITE_DONE;
        const int n = done ? sqlite3_changes(db_) : -1;
        st->reset();
        return n;
    };
    r.drops = wipe("DELETE FROM drops WHERE recipient=?1");
    r.journal = wipe("DELETE FROM journal WHERE fingerprint=?1");
    r.blobs = wipe("DELETE FROM blobs WHERE owner=?1");
    const int identity = wipe("DELETE FROM identities WHERE fingerprint=?1");
    wipe("DELETE FROM quotas WHERE fingerprint=?1");
    wipe("DELETE FROM account_ttls WHERE fingerprint=?1");
    if (r.drops < 0 || r.journal < 0 || r.blobs < 0 || identity < 0) {
        exec("ROLLBACK");
        return r;
    }

    if (auto* st = cached("SELECT 1 FROM blobs WHERE id=?1 LIMIT 1")) {
        for (const auto& id : candidates) {
            st->reset().text(1, id);
            if (st->step() != SQLITE_ROW) r.orphaned_blob_ids.push_back(id);
        }
        st->reset();
    }

    if (!exec("COMMIT")) {
        exec("ROLLBACK");
        return r;
    }
    r.ok = true;
    return r;
}

bool Db::set_account_ttl(const std::string& fingerprint, std::int64_t ttl_days) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("INSERT INTO account_ttls(fingerprint, ttl_days, updated_at)"
                      " VALUES(?1,?2,?3)"
                      " ON CONFLICT(fingerprint) DO UPDATE SET"
                      "  ttl_days=excluded.ttl_days, updated_at=excluded.updated_at");
    if (!st) return false;
    st->text(1, fingerprint).i64(2, ttl_days).i64(3, util::now_unix());
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok;
}

bool Db::clear_account_ttl(const std::string& fingerprint) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("DELETE FROM account_ttls WHERE fingerprint=?1");
    if (!st) return false;
    st->text(1, fingerprint);
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok;
}

std::int64_t Db::ttl_days_for(const std::string& fingerprint, std::int64_t default_days) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return default_days;
    auto* st = cached("SELECT ttl_days FROM account_ttls WHERE fingerprint=?1");
    if (!st) return default_days;
    st->text(1, fingerprint);
    std::int64_t days = default_days;
    if (st->step() == SQLITE_ROW) days = st->col_i64(0);
    st->reset();
    // -1 (keep forever) becomes a century: an expiry the sweep never reaches.
    return days < 0 ? 36500 : days;
}

// ------------------------------------------------------ storage market -----

bool Db::rental_create(const Rental& r) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached(
        "INSERT INTO rentals(id, fingerprint, bytes, price_micro, payment_key,"
        " created_at, paid_until, state) VALUES(?1,?2,?3,?4,?5,?6,?7,'active')");
    if (!st) return false;
    st->text(1, r.id).text(2, r.fingerprint).i64(3, r.bytes).i64(4, r.price_micro)
       .text(5, r.payment_key).i64(6, r.created_at).i64(7, r.paid_until);
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    // The renter leaves the free tier; refresh the pool memo eagerly.
    if (ok) free_tier_memo_ = -1;
    return ok;
}

std::int64_t Db::rentals_committed_bytes() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;
    auto* st = cached("SELECT IFNULL(SUM(bytes),0) FROM rentals"
                      " WHERE state='active' AND paid_until>?1");
    if (!st) return 0;
    st->i64(1, util::now_unix());
    std::int64_t total = 0;
    if (st->step() == SQLITE_ROW) total = st->col_i64(0);
    st->reset();
    return total;
}

std::optional<Db::Rental> Db::rental_get(const std::string& id) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return std::nullopt;
    auto* st = cached("SELECT fingerprint, bytes, price_micro, payment_key, created_at,"
                      " paid_until, state FROM rentals WHERE id=?1");
    if (!st) return std::nullopt;
    st->text(1, id);
    std::optional<Rental> out;
    if (st->step() == SQLITE_ROW) {
        Rental r;
        r.id = id;
        r.fingerprint = st->col_text(0);
        r.bytes = st->col_i64(1);
        r.price_micro = st->col_i64(2);
        r.payment_key = st->col_text(3);
        r.created_at = st->col_i64(4);
        r.paid_until = st->col_i64(5);
        r.state = st->col_text(6);
        out = std::move(r);
    }
    st->reset();
    return out;
}

std::int64_t Db::rental_renew(const std::string& id, const std::string& fingerprint,
                              std::int64_t epoch_seconds, std::int64_t max_ahead_seconds) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;
    const std::int64_t now = util::now_unix();
    auto* st = cached(
        "UPDATE rentals SET"
        " paid_until = MIN(MAX(paid_until, ?3) + ?4, ?3 + ?5), state='active'"
        " WHERE id=?1 AND fingerprint=?2 AND state!='closed'");
    if (!st) return 0;
    st->text(1, id).text(2, fingerprint).i64(3, now).i64(4, epoch_seconds)
       .i64(5, max_ahead_seconds);
    if (st->step() != SQLITE_DONE || sqlite3_changes(db_) == 0) {
        st->reset();
        return 0;
    }
    st->reset();
    free_tier_memo_ = -1;  // a lapsed renter may have just rejoined the market
    std::int64_t paid_until = 0;
    if (auto* q = cached("SELECT paid_until FROM rentals WHERE id=?1")) {
        q->text(1, id);
        if (q->step() == SQLITE_ROW) paid_until = q->col_i64(0);
        q->reset();
    }
    return paid_until;
}

std::vector<Db::Rental> Db::rentals_list(int limit) {
    std::vector<Rental> out;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return out;
    auto* st = cached("SELECT id, fingerprint, bytes, price_micro, payment_key,"
                      " created_at, paid_until, state FROM rentals"
                      " ORDER BY created_at DESC LIMIT ?1");
    if (!st) return out;
    st->i64(1, limit);
    while (st->step() == SQLITE_ROW) {
        Rental r;
        r.id = st->col_text(0);
        r.fingerprint = st->col_text(1);
        r.bytes = st->col_i64(2);
        r.price_micro = st->col_i64(3);
        r.payment_key = st->col_text(4);
        r.created_at = st->col_i64(5);
        r.paid_until = st->col_i64(6);
        r.state = st->col_text(7);
        out.push_back(std::move(r));
    }
    st->reset();
    return out;
}

int Db::rentals_lapse(std::int64_t now) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;
    auto* st = cached("UPDATE rentals SET state='lapsed'"
                      " WHERE state='active' AND paid_until<?1");
    if (!st) return 0;
    st->i64(1, now);
    st->step();
    st->reset();
    const int changed = sqlite3_changes(db_);
    // Lapsed renters fall back into the free tier for pool accounting.
    if (changed > 0) free_tier_memo_ = -1;
    return changed;
}

bool Db::voucher_store(const std::string& payment_key, const std::string& payout,
                       std::int64_t cumulative_micro, const std::string& sig,
                       const std::string& raw, std::int64_t* out_prev) {
    std::lock_guard<std::mutex> lock(mu_);
    if (out_prev) *out_prev = 0;
    if (!db_) return false;
    std::int64_t prev = 0;
    if (auto* q = cached("SELECT IFNULL(MAX(cumulative_micro),0) FROM vouchers"
                         " WHERE payment_key=?1 AND payout=?2")) {
        q->text(1, payment_key).text(2, payout);
        if (q->step() == SQLITE_ROW) prev = q->col_i64(0);
        q->reset();
    }
    if (out_prev) *out_prev = prev;
    if (cumulative_micro <= prev) return false;
    auto* st = cached("INSERT OR IGNORE INTO vouchers"
                      "(payment_key, payout, cumulative_micro, sig, raw, created_at)"
                      " VALUES(?1,?2,?3,?4,?5,?6)");
    if (!st) return false;
    st->text(1, payment_key).text(2, payout).i64(3, cumulative_micro).text(4, sig)
       .text(5, raw).i64(6, util::now_unix());
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok;
}

std::vector<Db::VoucherRow> Db::vouchers_latest() {
    std::vector<VoucherRow> out;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return out;
    // The cumulative format makes the newest voucher subsume the rest, so
    // settlement needs exactly one row per (payer, payout).
    auto* st = cached(
        "SELECT v.payment_key, v.payout, v.cumulative_micro, v.sig, v.created_at"
        " FROM vouchers v JOIN (SELECT payment_key, payout,"
        "   MAX(cumulative_micro) AS m FROM vouchers GROUP BY payment_key, payout) x"
        " ON v.payment_key=x.payment_key AND v.payout=x.payout AND v.cumulative_micro=x.m"
        " ORDER BY v.created_at DESC");
    if (!st) return out;
    while (st->step() == SQLITE_ROW) {
        VoucherRow r;
        r.payment_key = st->col_text(0);
        r.payout = st->col_text(1);
        r.cumulative_micro = st->col_i64(2);
        r.sig = st->col_text(3);
        r.created_at = st->col_i64(4);
        out.push_back(std::move(r));
    }
    st->reset();
    return out;
}

// -------------------------------------------------- invite activation ------

bool Db::identity_exists(const std::string& fingerprint) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("SELECT 1 FROM identities WHERE fingerprint=?1");
    if (!st) return false;
    st->text(1, fingerprint);
    const bool found = st->step() == SQLITE_ROW;
    st->reset();
    return found;
}

void Db::note_received(const std::string& fingerprint, std::int64_t n) {
    if (n <= 0) return;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return;
    auto* st = cached("UPDATE identities SET received=received+?2 WHERE fingerprint=?1");
    if (!st) return;
    st->text(1, fingerprint).i64(2, n);
    st->step();
    st->reset();
}

Db::VouchResult Db::vouch(const std::string& inviter, const std::string& invitee) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return VouchResult::error;
    // Only the identity whose code the invitee claimed may vouch for them.
    auto* q = cached("SELECT 1 FROM invites WHERE burned_by=?1 AND issued_by=?2 LIMIT 1");
    if (!q) return VouchResult::error;
    q->text(1, invitee).text(2, inviter);
    const bool theirs = q->step() == SQLITE_ROW;
    q->reset();
    if (!theirs) return VouchResult::not_your_invitee;
    auto* st = cached("UPDATE identities SET vouched_at=?2"
                      " WHERE fingerprint=?1 AND vouched_at IS NULL");
    if (!st) return VouchResult::error;
    st->text(1, invitee).i64(2, util::now_unix());
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok ? VouchResult::ok : VouchResult::error;
}

Db::Activation Db::activation(const std::string& fingerprint, std::int64_t min_received) {
    Activation a;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return a;
    auto* st = cached(
        "SELECT i.received, i.vouched_at,"
        " IFNULL((SELECT issued_by FROM invites WHERE burned_by=i.fingerprint"
        "         ORDER BY burned_at LIMIT 1), ''),"
        " IFNULL((SELECT p.pubkey FROM identities p WHERE p.fingerprint=(SELECT issued_by"
        "         FROM invites WHERE burned_by=i.fingerprint ORDER BY burned_at LIMIT 1)), '')"
        " FROM identities i WHERE i.fingerprint=?1");
    if (!st) return a;
    st->text(1, fingerprint);
    if (st->step() == SQLITE_ROW) {
        a.registered = true;
        a.received = st->col_i64(0);
        a.vouched = sqlite3_column_type(st->raw(), 1) != SQLITE_NULL;
        const std::string issuer = st->col_text(2);
        // Genesis, operator and open-registration codes have no inviting
        // identity to vouch; for them traffic alone activates.
        if (util::is_valid_fingerprint(issuer)) {
            a.vouch_required = true;
            a.inviter = issuer;
            a.inviter_pubkey = st->col_text(3);
        }
    }
    st->reset();
    a.active = a.registered && a.received >= min_received && (a.vouched || !a.vouch_required);
    return a;
}

int Db::activate_if_ready(const std::string& fingerprint, std::int64_t min_received) {
    if (!activation(fingerprint, min_received).active) return 0;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return 0;
    auto* st = cached("UPDATE invites SET locked=0 WHERE issued_by=?1 AND locked=1");
    if (!st) return 0;
    st->text(1, fingerprint);
    const int n = st->step() == SQLITE_DONE ? sqlite3_changes(db_) : 0;
    st->reset();
    return n;
}

std::vector<Db::OwnInvite> Db::invites_issued_by(const std::string& fingerprint) {
    std::vector<OwnInvite> out;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return out;
    auto* st = cached("SELECT code, burned_at IS NOT NULL, revoked_at IS NOT NULL, locked"
                      " FROM invites WHERE issued_by=?1 ORDER BY created_at, code");
    if (!st) return out;
    st->text(1, fingerprint);
    while (st->step() == SQLITE_ROW) {
        const char* state = st->col_i64(2) ? "revoked" : st->col_i64(1) ? "burned"
                            : st->col_i64(3) ? "locked" : "open";
        out.push_back({st->col_text(0), state});
    }
    st->reset();
    return out;
}

// --------------------------------------------------------- identities ------

bool Db::register_identity(const std::string& fingerprint, const std::string& home_relay,
                           const std::string& pubkey) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("INSERT INTO identities"
                      "(fingerprint, home_relay, pubkey, registered_at, last_seen)"
                      " VALUES(?1,?2,?3,?4,?4)"
                      " ON CONFLICT(fingerprint) DO UPDATE SET"
                      "  home_relay=excluded.home_relay,"
                      "  pubkey=CASE WHEN excluded.pubkey<>'' THEN excluded.pubkey"
                      "              ELSE identities.pubkey END,"
                      "  last_seen=excluded.last_seen");
    if (!st) return false;
    const std::int64_t now = util::now_unix();
    st->text(1, fingerprint).text(2, home_relay).text(3, pubkey).i64(4, now);
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok;
}

bool Db::set_identity_x25519(const std::string& fingerprint, const std::string& x25519_b64) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("UPDATE identities SET x25519=?2 WHERE fingerprint=?1 AND x25519<>?2");
    if (!st) return false;
    st->text(1, fingerprint).text(2, x25519_b64);
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok;
}

std::optional<std::string> Db::identity_x25519(const std::string& fingerprint) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return std::nullopt;
    auto* st = cached("SELECT x25519 FROM identities WHERE fingerprint=?1");
    if (!st) return std::nullopt;
    st->text(1, fingerprint);
    std::optional<std::string> out;
    if (st->step() == SQLITE_ROW) {
        auto v = st->col_text(0);
        if (!v.empty()) out = v;
    }
    st->reset();
    return out;
}

std::optional<std::string> Db::lookup_home_relay(const std::string& fingerprint) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return std::nullopt;
    auto* st = cached("SELECT home_relay FROM identities WHERE fingerprint=?1");
    if (!st) return std::nullopt;
    st->text(1, fingerprint);
    std::optional<std::string> out;
    if (st->step() == SQLITE_ROW) {
        auto v = st->col_text(0);
        if (!v.empty()) out = v;
    }
    st->reset();
    return out;
}

void Db::touch_identity(const std::string& fingerprint) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return;
    auto* st = cached("UPDATE identities SET last_seen=?1 WHERE fingerprint=?2");
    if (!st) return;
    // Rounded to the hour: enough to expire dormant rows, too coarse to be a
    // presence log.
    const std::int64_t hour = (util::now_unix() / 3600) * 3600;
    st->i64(1, hour).text(2, fingerprint);
    st->step();
    st->reset();
}

// --------------------------------------------------------------- misc ------

Db::Stats Db::stats() {
    Stats s;
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return s;
    if (auto* st = cached("SELECT COUNT(*), IFNULL(SUM(LENGTH(payload)),0) FROM drops")) {
        if (st->step() == SQLITE_ROW) {
            s.drops_stored = st->col_i64(0);
            s.drop_bytes = st->col_i64(1);
        }
        st->reset();
    }
    if (auto* st = cached("SELECT COUNT(*) FROM identities")) {
        if (st->step() == SQLITE_ROW) s.identities = st->col_i64(0);
        st->reset();
    }
    if (auto* st = cached("SELECT SUM(burned_at IS NULL AND revoked_at IS NULL),"
                          " SUM(burned_at IS NOT NULL), SUM(revoked_at IS NOT NULL)"
                          " FROM invites")) {
        if (st->step() == SQLITE_ROW) {
            s.invites_unused = st->col_i64(0);
            s.invites_burned = st->col_i64(1);
            s.invites_revoked = st->col_i64(2);
        }
        st->reset();
    }
    return s;
}

std::optional<std::string> Db::meta_get(const std::string& key) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return std::nullopt;
    auto* st = cached("SELECT v FROM meta WHERE k=?1");
    if (!st) return std::nullopt;
    st->text(1, key);
    std::optional<std::string> out;
    if (st->step() == SQLITE_ROW) out = st->col_text(0);
    st->reset();
    return out;
}

bool Db::meta_set(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    auto* st = cached("INSERT INTO meta(k,v) VALUES(?1,?2)"
                      " ON CONFLICT(k) DO UPDATE SET v=excluded.v");
    if (!st) return false;
    st->text(1, key).text(2, value);
    const bool ok = st->step() == SQLITE_DONE;
    st->reset();
    return ok;
}

bool Db::checkpoint() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!db_) return false;
    return exec("PRAGMA wal_checkpoint(TRUNCATE)");
}

}  // namespace r2r
