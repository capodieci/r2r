// R2R relay -- SQLite persistence (statically linked amalgamation).
//
// WHAT IS STORED
//   drops       ciphertext blobs addressed to a recipient fingerprint, with a
//               hard expiry (default 7 days). The relay cannot read them.
//   invites     single-use UUID codes and the moment they were burned.
//   identities  fingerprint -> home relay, so other nodes know where to leave
//               mail for someone.
//
// WHAT IS NEVER STORED
//   IP addresses, ports, user agents, hostnames of clients, plaintext,
//   contact graphs, or per-message sender identities. `from_hint` is an
//   optional opaque token chosen by the sender's client; it is not verified
//   and may be empty.
#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "util.hpp"

struct sqlite3;
struct sqlite3_stmt;

namespace r2r {

class Db {
public:
    struct Drop {
        std::int64_t seq{0};  // insertion order; the only safe fetch cursor
        std::string id;
        std::string recipient;
        std::string from_hint;
        util::Bytes payload;
        std::int64_t created_at{0};
        std::int64_t expires_at{0};
    };

    struct Stats {
        std::int64_t drops_stored{0};
        std::int64_t drop_bytes{0};
        std::int64_t identities{0};
        std::int64_t invites_unused{0};
        std::int64_t invites_burned{0};
        std::int64_t invites_revoked{0};
    };

    enum class StoreResult { ok, duplicate, quota_exceeded, error };
    enum class ClaimResult { ok, not_found, already_used, revoked, locked, already_registered, error };

    // Per-recipient storage allowance. The relay owner raises an individual
    // user's limit with `r2r-relay --set-quota <fingerprint> <MB>`; anyone
    // without a row gets the relay default.
    struct Quota {
        std::int64_t max_bytes{0};
        std::int64_t max_drops{0};
        std::int64_t used_bytes{0};
        std::int64_t used_drops{0};
        bool custom{false};  // false -> falling back to the relay default
    };

    // Both are defined in db.cpp: Stmt is incomplete here on purpose, so the
    // sqlite3 headers stay out of every translation unit that touches storage.
    Db();
    ~Db();
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;

    // Opens the database, applies pragmas and migrations. Returns false and
    // logs on failure.
    bool open(const std::string& path);
    void close();

    void set_quota(std::int64_t max_drops_per_recipient, std::int64_t max_bytes_per_recipient);
    // Cap on the combined storage of every identity on the default quota
    // (the "common good" pool). 0 = unlimited. Custom-quota identities are
    // governed by their own quota only.
    void set_common_pool(std::int64_t max_bytes);
    // Bytes currently held for default-quota identities (memoised, refreshed
    // every 30 s and bumped on accepted stores, so enforcement stays tight).
    std::int64_t free_tier_used_bytes();

    // --- dead drops --------------------------------------------------------
    // `out_seq`, when given, receives the stored row's sequence number -- the
    // same cursor value a fetch would return -- so a live push can carry it.
    StoreResult store_drop(const std::string& id, const std::string& recipient,
                           const void* payload, std::size_t len, const std::string& from_hint,
                           std::int64_t created_at, std::int64_t expires_at,
                           std::int64_t* out_seq = nullptr);
    // `after_seq` is exclusive. Timestamps are unusable as a cursor: two
    // payloads stored in the same second would make the client skip one.
    std::vector<Drop> fetch_drops(const std::string& recipient, std::int64_t after_seq, int limit);
    int ack_drops(const std::string& recipient, const std::vector<std::string>& ids);
    std::int64_t pending_for(const std::string& recipient);
    int prune_expired(std::int64_t now);

    // --- journal -----------------------------------------------------------
    // An append-only, per-identity log of ciphertext the client writes about
    // its own conversations. Replaying it is how a fresh browser rebuilds a
    // user's message history.
    struct JournalEntry {
        std::int64_t seq{0};
        util::Bytes data;
        std::int64_t created_at{0};
    };
    enum class AppendResult { ok, quota_exceeded, error };
    AppendResult journal_append(const std::string& fingerprint, const void* data, std::size_t len,
                                std::int64_t& out_seq);
    std::vector<JournalEntry> journal_read(const std::string& fingerprint, std::int64_t after_seq,
                                           int limit, std::size_t max_bytes,
                                           bool* truncated = nullptr);

    // --- blobs -------------------------------------------------------------
    // Voice and video messages. Content-addressed, so the same recording
    // uploaded twice is stored once; a row per (id, owner) keeps the accounting
    // honest and lets each owner's retention run independently.
    enum class BlobResult { ok, duplicate, quota_exceeded, error };
    BlobResult blob_record(const std::string& id, const std::string& owner, std::int64_t size,
                           std::int64_t expires_at);
    bool blob_exists(const std::string& id);
    std::int64_t blob_size(const std::string& id);
    // Removes expired references and returns the ids nothing refers to any
    // more, so their bytes can be deleted from disk.
    std::vector<std::string> prune_blobs(std::int64_t now);
    std::int64_t count_blobs();

    // --- relay owners ------------------------------------------------------
    // An owner is an ordinary identity that the operator has marked as
    // trusted on this relay. There is no separate admin password to leak or
    // paste around: the wallet already holds an ed25519 key and proves it on
    // every connection, so owner actions reuse exactly that proof.
    bool owner_add(const std::string& fingerprint);
    bool owner_remove(const std::string& fingerprint);
    bool owner_is(const std::string& fingerprint);
    std::vector<std::string> owner_list();
    std::int64_t owner_count();

    struct Account {
        std::string fingerprint;
        std::string home_relay;
        std::int64_t registered_at{0};
        std::int64_t last_seen{0};
        std::int64_t used_bytes{0};
        std::int64_t quota_bytes{0};
        bool custom_quota{false};
    };
    std::vector<Account> list_accounts(int limit, int offset);

    // --- quotas ------------------------------------------------------------
    Quota quota_for(const std::string& fingerprint);
    bool set_quota_bytes(const std::string& fingerprint, std::int64_t max_bytes);
    bool clear_quota(const std::string& fingerprint);
    std::vector<std::pair<std::string, std::int64_t>> list_quotas();

    // --- invites -----------------------------------------------------------
    bool invite_is_open(const std::string& code);
    // `hint_hex` is the optional 8-hex-char IPv4 routing hint baked into codes
    // minted here (see crypto::invite_code). Codes minted as part of a claim
    // record the claimed code as their `parent_code`, which is what the
    // revoke cascade walks.
    ClaimResult claim_invite(const std::string& code, const std::string& fingerprint,
                             const std::string& home_relay, const std::string& pubkey,
                             int new_code_count, const std::string& hint_hex,
                             std::vector<std::string>& out_codes);
    std::vector<std::string> mint_invites(int n, const std::string& issued_by,
                                          const std::string& hint_hex = {},
                                          const std::string& parent_code = {},
                                          bool locked = false);

    // --- invite activation ---------------------------------------------------
    // Codes a member receives start locked. They unlock once the member has
    // used the network: `min_received` payloads received and acknowledged
    // since registering, and -- when an identity invited them -- a vouch from
    // that inviter, which the inviter's wallet sends after a two-way chat.
    bool identity_exists(const std::string& fingerprint);
    void note_received(const std::string& fingerprint, std::int64_t n);
    enum class VouchResult { ok, not_your_invitee, error };
    VouchResult vouch(const std::string& inviter, const std::string& invitee);
    struct Activation {
        bool registered{false};
        std::int64_t received{0};
        bool vouch_required{false};
        bool vouched{false};
        std::string inviter;          // fingerprint, empty when genesis/operator/open
        std::string inviter_pubkey;   // b64, may be empty
        bool active{false};
    };
    Activation activation(const std::string& fingerprint, std::int64_t min_received);
    // Unlocks the member's codes when activation(...).active. Returns how many.
    int activate_if_ready(const std::string& fingerprint, std::int64_t min_received);
    struct OwnInvite {
        std::string code;
        std::string state;  // "locked" | "open" | "burned" | "revoked"
    };
    std::vector<OwnInvite> invites_issued_by(const std::string& fingerprint);
    // Marks a code revoked, and with `cascade` every open descendant too.
    // Claimed codes and the identities they created are never touched.
    struct RevokeResult {
        bool found{false};
        int direct{0};    // 1 if the named code itself was open and revoked
        int cascaded{0};  // open descendants revoked
    };
    RevokeResult revoke_invite(const std::string& code, bool cascade,
                               const std::string& revoked_by);

    // --- doorway lookups ----------------------------------------------------
    struct InviteInfo {
        bool found{false};
        bool burned{false};
        bool revoked{false};
        bool locked{false};
        std::string issued_by;
        std::string contact_token;
    };
    InviteInfo invite_info(const std::string& code);

    // Burns an open code for a web redemption and records the setup card's
    // key hash in the same transaction. `race` when the code was consumed or
    // revoked between the preview and the POST.
    enum class CardRedeemResult { ok, race, error };
    CardRedeemResult redeem_for_card(const std::string& code, const std::string& card_key_hash);

    struct ContactInfo {
        bool found{false};
        bool revoked{false};
        std::string fingerprint;   // identity that minted the invite
        std::string pubkey_b64;    // its stored public key, may be empty
    };
    ContactInfo contact_info(const std::string& token);

    // --- admin console ------------------------------------------------------
    struct InviteRow {
        std::string code;
        std::int64_t created_at{0};
        std::string issued_by;
        std::string parent_code;
        bool has_contact_token{false};
        std::string state;  // "open" | "burned" | "revoked"
        std::int64_t burned_at{0};
        std::string burned_by;
        std::int64_t revoked_at{0};
        std::string revoked_by;
    };
    // `state` filters to one state; empty or "all" lists everything.
    std::vector<InviteRow> list_invites(int limit, int offset, const std::string& state);

    // Accounts whose fingerprint starts with `q` (hex) or whose home relay
    // contains it. Same shape as list_accounts.
    std::vector<Account> search_accounts(const std::string& q, int limit);

    // Removes an identity and everything it stores. Returns the blob ids that
    // no longer have any owner, so their bytes can be deleted from disk.
    struct DeleteResult {
        bool ok{false};
        int drops{0};
        int journal{0};
        int blobs{0};
        std::vector<std::string> orphaned_blob_ids;
    };
    DeleteResult delete_account(const std::string& fingerprint);

    // Per-account retention override; -1 = keep forever.
    bool set_account_ttl(const std::string& fingerprint, std::int64_t ttl_days);
    bool clear_account_ttl(const std::string& fingerprint);
    // The retention to apply for this account: its override, else the default.
    std::int64_t ttl_days_for(const std::string& fingerprint, std::int64_t default_days);

    // --- mail pointers ------------------------------------------------------
    struct Pointer {
        std::string address;
        std::int64_t count{0};
        std::int64_t created_at{0};
    };
    // Upserts one verified pointer; a newer statement for the same
    // (fingerprint, holder) pair replaces the older one.
    bool pointer_store(const std::string& fingerprint, const std::string& address,
                       std::int64_t count, const std::string& node_id,
                       const std::string& ed25519_b64, const std::string& sig_b64,
                       std::int64_t created_at, std::int64_t expires_at);
    std::vector<Pointer> pointers_for(const std::string& fingerprint);
    int prune_pointers(std::int64_t now);
    bool pointer_delete(const std::string& fingerprint, const std::string& address);

    // --- safe deposit -------------------------------------------------------
    // Records a collection nonce; false when it was already presented.
    bool authz_burn(const std::string& nonce);
    int prune_authz(std::int64_t before);
    // Deletes a set of this recipient's drops in one transaction (the holder
    // side of collect-delete). Returns how many rows went.
    int delete_drops(const std::string& recipient, const std::vector<std::string>& ids);

    // --- storage market -----------------------------------------------------
    // A rental reserves bytes from the market pool for one identity. Its
    // bytes count as extra allowance in every store path while paid, and the
    // sum of active rentals is the committed inventory -- the relay never
    // promises bytes it has not budgeted.
    struct Rental {
        std::string id;
        std::string fingerprint;
        std::int64_t bytes{0};
        std::int64_t price_micro{0};  // per epoch, fixed at rent time
        std::string payment_key;
        std::int64_t created_at{0};
        std::int64_t paid_until{0};
        std::string state;  // "active" | "lapsed" | "closed"
    };
    bool rental_create(const Rental& r);
    // Sum of bytes reserved by paid rentals (state active, not yet lapsed).
    std::int64_t rentals_committed_bytes();
    std::optional<Rental> rental_get(const std::string& id);
    // Extends paid_until by `epoch_seconds` from max(now, paid_until), capped
    // at now + max_ahead_seconds. Returns the new paid_until, or 0 when the
    // rental does not exist or belongs to someone else.
    std::int64_t rental_renew(const std::string& id, const std::string& fingerprint,
                              std::int64_t epoch_seconds, std::int64_t max_ahead_seconds);
    std::vector<Rental> rentals_list(int limit);
    // Marks overdue rentals lapsed; returns how many changed.
    int rentals_lapse(std::int64_t now);

    // Settlement vouchers, stored verbatim for the operator to redeem, after
    // Hub::handle_voucher has recovered the signer and matched the rental.
    // Returns false when this cumulative does not exceed the highest voucher
    // already held for (payment_key, payout); `out_prev` gets that maximum.
    bool voucher_store(const std::string& payment_key, const std::string& payout,
                       std::int64_t cumulative_micro, const std::string& sig,
                       const std::string& raw, std::int64_t* out_prev = nullptr);
    struct VoucherRow {
        std::string payment_key;
        std::string payout;
        std::int64_t cumulative_micro{0};
        std::string sig;
        std::int64_t created_at{0};
    };
    // Newest (highest cumulative) voucher per (payment_key, payout).
    std::vector<VoucherRow> vouchers_latest();

    // --- identities --------------------------------------------------------
    bool register_identity(const std::string& fingerprint, const std::string& home_relay,
                           const std::string& pubkey);
    std::optional<std::string> lookup_home_relay(const std::string& fingerprint);
    void touch_identity(const std::string& fingerprint);
    // Records the wallet's curve25519 public key (b64) for a registered
    // identity; a no-op for unknown fingerprints. Overwrites only when the
    // value changed, so repeated hellos stay cheap.
    bool set_identity_x25519(const std::string& fingerprint, const std::string& x25519_b64);
    std::optional<std::string> identity_x25519(const std::string& fingerprint);

    // --- misc --------------------------------------------------------------
    Stats stats();
    std::optional<std::string> meta_get(const std::string& key);
    bool meta_set(const std::string& key, const std::string& value);
    bool checkpoint();

private:
    class Stmt;
    Stmt* cached(const char* sql);          // caller holds mu_
    bool exec(const char* sql);             // caller holds mu_
    bool migrate();                         // caller holds mu_

    // Caller holds mu_. True when this store would take the free tier past
    // the common pool cap; refreshes/bumps the memo as a side effect.
    bool common_pool_exceeded(const std::string& fingerprint, std::int64_t add_bytes);
    std::int64_t free_tier_bytes_locked();  // caller holds mu_
    // Caller holds mu_. (custom quota | relay default) + active rented bytes.
    std::int64_t allowance_locked(const std::string& fingerprint);

    sqlite3* db_{nullptr};
    std::mutex mu_;
    std::unordered_map<std::string, std::unique_ptr<Stmt>> stmts_;
    std::int64_t max_drops_per_recipient_{4096};
    std::int64_t max_bytes_per_recipient_{64 * 1024 * 1024};
    std::int64_t common_pool_bytes_{0};       // 0 = unlimited
    std::int64_t free_tier_memo_{-1};         // -1 = stale
    std::int64_t free_tier_memo_at_{0};
};

}  // namespace r2r
