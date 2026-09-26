#include "hub.hpp"

#include "blobstore.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>

#include "crypto.hpp"
#include "log.hpp"
#include "onion.hpp"
#include "protocol.hpp"

using nlohmann::json;

namespace r2r {
namespace {

constexpr std::int64_t kHelloClockSkewSeconds = 300;
constexpr std::size_t kMaxGossipEntries = 128;
constexpr int kFetchDefaultLimit = 64;
constexpr int kFetchMaxLimit = 128;
constexpr int kInvitesPerClaim = 3;
constexpr int kRateStrikeLimit = 200;
constexpr std::int64_t kClientClockSkewSeconds = 600;
constexpr std::size_t kMaxWatchList = 512;

std::string digest_key(const util::Bytes& blob) {
    return util::hex_encode(crypto::sha256(blob.data(), blob.size())).substr(0, 32);
}

}  // namespace

// ------------------------------------------------------------ SeenCache ----

SeenCache::SeenCache(std::int64_t ttl_seconds, std::size_t cap) : ttl_(ttl_seconds), cap_(cap) {}

void SeenCache::expire(std::int64_t now) {
    while (!order_.empty() && (order_.front().first + ttl_ < now || set_.size() > cap_)) {
        set_.erase(order_.front().second);
        order_.pop_front();
    }
}

bool SeenCache::insert(const std::string& key) {
    const std::int64_t now = util::now_unix();
    std::lock_guard<std::mutex> lock(mu_);
    expire(now);
    if (!set_.insert(key).second) return false;
    order_.emplace_back(now, key);
    return true;
}

std::size_t SeenCache::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return set_.size();
}

// ------------------------------------------------------------------ Hub ----

Hub::Hub(const Config& cfg, Db& db, PeerRegistry& peers, const crypto::NodeIdentity& node)
    : cfg_(cfg), db_(db), peers_(peers), node_(node), seen_(900, 200000) {
    if (!cfg.advertise.empty()) {
        bool tls = false;
        if (auto canon = PeerRegistry::canonicalise(cfg.advertise, tls)) self_address_ = *canon;
    }
}

Hub::SessionPtr Hub::session_for(const std::string& conn_id) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = sessions_.find(conn_id);
    return it == sessions_.end() ? nullptr : it->second;
}

void Hub::send_json(const ConnectionPtr& c, const json& j) {
    if (!c) return;
    c->send_text(j.dump());
    frames_out_.fetch_add(1, std::memory_order_relaxed);
}

// Error frames are themselves rate limited, and never sent in reply to an
// error. Two relays that each answered "I do not understand that" would
// otherwise trade frames until the link saturated.
void Hub::send_error(const ConnectionPtr& c, std::string_view code, std::string_view msg,
                     std::string_view ref) {
    if (!c) return;
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = sessions_.find(c->id());
        if (it != sessions_.end() &&
            !it->second->err_bucket.consume(1.0, util::steady_ms()))
            return;  // drop it silently rather than feed a loop
    }
    send_json(c, proto::make_error(code, msg, ref));
}

json Hub::identity_frame(const char* type) const {
    const std::int64_t ts = util::now_unix();
    const std::string nonce = util::hex_encode(crypto::random_bytes(12));

    json j;
    j["t"] = type;
    j["proto"] = proto::kVersion;
    j["role"] = "relay";
    j["node_id"] = node_.node_id();
    j["advertise"] = self_address();
    j["ed25519"] = node_.ed_pub_b64();
    j["x25519"] = node_.x_pub_b64();
    j["tls"] = cfg_.tls_enabled;
    j["ws_port"] = cfg_.ws_port;
    j["wss_port"] = cfg_.tls_enabled ? cfg_.wss_port : 0;
    j["ts"] = ts;
    j["nonce"] = nonce;
    j["version"] = R2R_VERSION;

    if (auto sig = node_.sign(proto::hello_signing_string(node_.node_id(), self_address(), ts, nonce)))
        j["sig"] = util::b64_encode(*sig);
    return j;
}

// ------------------------------------------------------- channel events ----

void Hub::on_open(const ConnectionPtr& c) {
    auto s = std::make_shared<Session>();
    s->conn = c;
    s->connected_at = util::now_unix();
    s->bucket = util::TokenBucket(cfg_.rate_frames_per_sec, cfg_.rate_burst);
    s->err_bucket = util::TokenBucket(2.0, 6.0);

    {
        std::lock_guard<std::mutex> lock(mu_);
        sessions_.emplace(c->id(), s);
    }

    if (c->kind() == ConnKind::outbound_peer) {
        log::debug("peer link up to ", c->dialled_address(), " (", c->secure() ? "wss" : "ws", ")");
        send_json(c, identity_frame(proto::kHello));
    } else {
        log::debug("inbound connection ", c->id(), " (", c->secure() ? "wss" : "ws", ")");
    }
}

void Hub::on_close(const ConnectionPtr& c) {
    SessionPtr s;
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = sessions_.find(c->id());
        if (it == sessions_.end()) return;
        s = it->second;
        identity = s->identity;
        if (!identity.empty()) last_seen_[identity] = util::now_unix();
        unindex(s);
        sessions_.erase(it);
    }
    // Told after the session is gone, so watchers see the state that now holds.
    if (!identity.empty()) push_presence(identity);
    if (c->kind() == ConnKind::outbound_peer)
        log::debug("peer link to ", c->dialled_address(), " closed");
}

void Hub::on_text(const ConnectionPtr& c, std::string&& msg) {
    frames_in_.fetch_add(1, std::memory_order_relaxed);

    auto s = session_for(c->id());
    if (!s) return;

    if (msg.size() > cfg_.max_frame_bytes) {
        send_error(c, proto::kErrTooBig, "frame exceeds the relay's size limit");
        return;
    }

    bool throttled = false;
    int strikes = 0;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!s->bucket.consume(1.0, util::steady_ms())) {
            throttled = true;
            strikes = ++s->rate_strikes;
        } else {
            s->rate_strikes = 0;
        }
    }
    if (throttled) {
        // A peer that ignores back-pressure for this long is malfunctioning,
        // not merely busy.
        if (strikes > kRateStrikeLimit) {
            log::warn("closing connection ", c->id(), ": sustained rate limit violation");
            c->close_now(1013, "rate limit");
            return;
        }
        send_error(c, proto::kErrRateLimited, "slow down");
        return;
    }

    json j = json::parse(msg, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        send_error(c, proto::kErrBadFrame, "expected a JSON object");
        return;
    }
    // Handlers read typed fields (j.value("ts", 0) and friends), which throw
    // when a peer sends the wrong JSON type. Nothing above this frame may be
    // allowed to see that: an uncaught exception unwinds out of the
    // io_context and takes the whole relay down with it.
    try {
        handle_frame(s, j);
    } catch (const json::exception&) {
        send_error(c, proto::kErrBadField, "a field has the wrong type");
    } catch (const std::exception& e) {
        log::warn("frame on connection ", c->id(), " failed: ", e.what());
        send_error(c, proto::kErrInternal, "could not process the frame");
    }
}

void Hub::handle_frame(const SessionPtr& s, const json& j) {
    if (!j.contains("t") || !j["t"].is_string()) {
        send_error(s->conn, proto::kErrBadFrame, "missing frame type");
        return;
    }
    const std::string t = j["t"].get<std::string>();

    // An error is a dead end: replying to one is how a link turns into a storm.
    if (t == proto::kError) {
        log::debug("peer on connection ", s->conn->id(), " reported ",
                   j.value("code", std::string{"?"}));
        return;
    }
    // Frames that are replies to something we asked for. A relay can legitimately
    // receive them (it forwards on behalf of clients) and has nothing to say back.
    if (t == proto::kSent || t == proto::kDrop || t == proto::kFetchDone ||
        t == proto::kInviteOk || t == proto::kMail || t == "ack_ok")
        return;

    if (t == proto::kHello) return handle_identity(s, j, false);
    if (t == proto::kWelcome) return handle_identity(s, j, true);
    if (t == proto::kSend) return handle_send(s, j);
    if (t == proto::kOnion) return handle_onion(s, j);
    if (t == proto::kFetch) return handle_fetch(s, j);
    if (t == proto::kAck) return handle_ack(s, j);
    if (t == proto::kPing) return handle_ping(s, j);
    if (t == proto::kPong) return handle_pong(s, j);
    if (t == proto::kPeersReq) return handle_peers_req(s);
    if (t == proto::kPeers) return handle_peers(s, j);
    if (t == proto::kPointer) return handle_pointer(s, j);
    if (t == proto::kLocate) return handle_locate(s);
    if (t == proto::kLocated || t == proto::kMailAt) return;
    if (t == proto::kDeposit) return handle_deposit(s, j);
    if (t == proto::kCollect) return handle_collect(s, j);
    if (t == proto::kCollectItem) return handle_collect_item(s, j);
    if (t == proto::kCollectDone) return handle_collect_done(s, j);
    if (t == proto::kDepositOk) return;
    if (t == proto::kInviteClaim) return handle_invite_claim(s, j);
    if (t == proto::kVouch) return handle_vouch(s, j);
    if (t == proto::kInviteStatus) return handle_invite_status(s);
    if (t == proto::kVouchOk) return;
    if (t == proto::kSubscribe) return handle_subscribe(s, j);
    if (t == proto::kQuota) return handle_quota(s);
    if (t == proto::kSig) return handle_sig(s, j);
    if (t == proto::kIce) return handle_ice(s);
    if (t == proto::kWatch) return handle_watch(s, j);
    if (t == proto::kPresence) return handle_presence(s, j);
    if (t == proto::kJournalAppend) return handle_journal_append(s, j);
    if (t == proto::kJournalRead) return handle_journal_read(s, j);
    if (t == proto::kJournal || t == proto::kJournalOk) return;
    if (t == proto::kRent) return handle_rent(s, j);
    if (t == proto::kVoucher) return handle_voucher(s, j);
    if (t == proto::kRentOk || t == proto::kVoucherOk) return;
    if (t == proto::kAdminAccounts) return handle_admin_accounts(s, j);
    if (t == proto::kAdminSetQuota) return handle_admin_set_quota(s, j);
    if (t == proto::kAdminInvites) return handle_admin_invites(s, j);
    if (t == proto::kAdminRevokeInvite) return handle_admin_revoke_invite(s, j);
    if (t == proto::kAdminListInvites) return handle_admin_list_invites(s, j);
    if (t == proto::kAdminSetTtl) return handle_admin_set_ttl(s, j);
    if (t == proto::kAdminSearchAccounts) return handle_admin_search_accounts(s, j);
    if (t == proto::kAdminDeleteAccount) return handle_admin_delete_account(s, j);
    if (t == proto::kAdminSetAdvertise) return handle_admin_set_advertise(s, j);
    if (t == proto::kAdminListRentals) return handle_admin_list_rentals(s);
    if (t == proto::kAdminListVouchers) return handle_admin_list_vouchers(s);
    if (t == proto::kAdminOk) return;
    if (t == proto::kBye) {
        s->conn->close_now(1000, "bye");
        return;
    }
    send_error(s->conn, proto::kErrUnknownType, "unsupported frame type", t);
}

// ------------------------------------------------------------ handshake ----

Hub::PeerClaim Hub::verify_peer_claim(const json& j) const {
    PeerClaim c;
    const std::string node_id = j.value("node_id", std::string{});
    const std::string advertise = j.value("advertise", std::string{});
    const std::string ed_b64 = j.value("ed25519", std::string{});
    const std::string x_b64 = j.value("x25519", std::string{});
    const std::string sig_b64 = j.value("sig", std::string{});
    const std::string nonce = j.value("nonce", std::string{});
    const std::int64_t ts = j.value("ts", std::int64_t{0});

    if (node_id.empty() || advertise.empty() || ed_b64.empty() || sig_b64.empty()) return c;
    if (nonce.size() < 16 || nonce.size() > 64) return c;
    if (std::llabs(static_cast<long long>(util::now_unix() - ts)) > kHelloClockSkewSeconds) return c;

    auto ed = util::b64_decode(ed_b64);
    auto sig = util::b64_decode(sig_b64);
    if (!ed || ed->size() != crypto::kPubLen || !sig) return c;
    if (crypto::node_id_from_ed_pub(*ed) != node_id) return c;
    if (!crypto::verify_signature(*ed, proto::hello_signing_string(node_id, advertise, ts, nonce),
                                  *sig))
        return c;
    if (node_id == node_.node_id()) return c;  // that is us on the other end

    // `advertise` is the plain ws:// address peers dial; `tls` only says the
    // relay also listens on wss_port. Canonicalise as plain, so a bare host
    // gets 8787 and the peer is never dialled with TLS on its plaintext port.
    const bool tls = j.value("tls", false);
    bool plain = false;
    auto canon = PeerRegistry::canonicalise(advertise, plain);
    if (!canon) return c;

    if (!x_b64.empty()) {
        auto x = util::b64_decode(x_b64);
        if (!x || x->size() != crypto::kPubLen) return c;
        c.x25519 = x_b64;
    }

    c.ok = true;
    c.node_id = node_id;
    c.advertise = *canon;
    c.ed25519 = ed_b64;
    c.tls = tls;
    return c;
}

Hub::ClientProof Hub::verify_client_proof(const json& j) const {
    ClientProof p;
    const std::string id = util::to_lower(util::trim(j.value("id", std::string{})));
    const std::string pub_b64 = j.value("pubkey", std::string{});
    const std::string sig_b64 = j.value("sig", std::string{});
    const std::string nonce = j.value("nonce", std::string{});
    const std::int64_t ts = j.value("ts", std::int64_t{0});

    if (!util::is_valid_fingerprint(id)) {
        p.error = proto::kErrBadField;
        return p;
    }
    if (pub_b64.empty() || sig_b64.empty() || nonce.size() < 16 || nonce.size() > 64) {
        p.error = proto::kErrNotAuthorised;
        return p;
    }
    if (std::llabs(static_cast<long long>(util::now_unix() - ts)) > kClientClockSkewSeconds) {
        p.error = proto::kErrNotAuthorised;
        return p;
    }
    auto pub = util::b64_decode(pub_b64);
    auto sig = util::b64_decode(sig_b64);
    if (!pub || pub->size() != crypto::kPubLen || !sig) {
        p.error = proto::kErrNotAuthorised;
        return p;
    }
    // The fingerprint has to be the hash of the key that produced the
    // signature; otherwise a valid signature from any key would do.
    if (crypto::fingerprint(*pub) != id) {
        p.error = proto::kErrNotAuthorised;
        return p;
    }
    if (!crypto::verify_signature(*pub, proto::client_auth_string(id, ts, nonce), *sig)) {
        p.error = proto::kErrNotAuthorised;
        return p;
    }
    // A proof is spent the moment it verifies. The seen cache outlives the
    // ±600 s clock window, so a captured proof cannot be presented a second
    // time, on the socket or in an X-R2R-Auth header. Wallets sign a fresh
    // nonce per use, so nothing legitimate is refused.
    if (!seen_.insert("c:" + id + "|" + nonce)) {
        log::debug("proof for ", log::short_id(id), " presented twice; the replay is refused");
        p.error = proto::kErrNotAuthorised;
        return p;
    }
    p.ok = true;
    p.fingerprint = id;
    p.pubkey_b64 = pub_b64;
    return p;
}

void Hub::index_relay(const SessionPtr& s, const PeerClaim& claim) {
    std::lock_guard<std::mutex> lock(mu_);
    s->role = Role::relay;
    s->node_id = claim.node_id;
    s->peer_address = claim.advertise;
    by_peer_address_[claim.advertise] = s->conn->id();
    by_node_id_[claim.node_id] = s->conn->id();
    if (s->conn->kind() == ConnKind::outbound_peer && !s->conn->dialled_address().empty())
        by_peer_address_[s->conn->dialled_address()] = s->conn->id();
}

void Hub::unindex(const SessionPtr& s) {
    // caller holds mu_
    const std::string& cid = s->conn->id();
    if (!s->identity.empty()) {
        auto range = by_identity_.equal_range(s->identity);
        for (auto it = range.first; it != range.second;) {
            if (it->second == cid) it = by_identity_.erase(it);
            else ++it;
        }
    }
    if (!s->peer_address.empty()) {
        auto it = by_peer_address_.find(s->peer_address);
        if (it != by_peer_address_.end() && it->second == cid) by_peer_address_.erase(it);
    }
    if (!s->conn->dialled_address().empty()) {
        auto it = by_peer_address_.find(s->conn->dialled_address());
        if (it != by_peer_address_.end() && it->second == cid) by_peer_address_.erase(it);
    }
    if (!s->node_id.empty()) {
        auto it = by_node_id_.find(s->node_id);
        if (it != by_node_id_.end() && it->second == cid) by_node_id_.erase(it);
    }
    for (const auto& watched : s->watching) {
        auto it = watchers_.find(watched);
        if (it == watchers_.end()) continue;
        it->second.erase(cid);
        if (it->second.empty()) watchers_.erase(it);
    }
    s->watching.clear();
}

void Hub::handle_identity(const SessionPtr& s, const json& j, bool is_welcome) {
    const std::string role = j.value("role", std::string{"client"});

    if (role == "relay") {
        // A dial that loops back to this very process: not an error, just an
        // address worth forgetting.
        if (j.value("node_id", std::string{}) == node_.node_id()) {
            if (s->conn->kind() == ConnKind::outbound_peer)
                peers_.mark_self_alias(s->conn->dialled_address());
            s->conn->close_now(1000, "self");
            return;
        }

        auto claim = verify_peer_claim(j);
        if (!claim.ok) {
            log::warn("rejecting relay handshake on connection ", s->conn->id(),
                      ": signature or node id did not verify");
            send_error(s->conn, proto::kErrNotAuthorised, "relay handshake failed");
            s->conn->close_now(1008, "handshake failed");
            return;
        }

        const bool outbound = s->conn->kind() == ConnKind::outbound_peer;
        const std::string dialled = outbound ? s->conn->dialled_address() : std::string{};

        // Trust on first use: once an address this relay has reached is pinned
        // to an ed25519 key, a different key for it is an impersonation
        // attempt. Only verified entries carry a pin; a key that merely arrived
        // by gossip or in someone's hello is a hint and proves nothing, so it
        // must not be able to lock a genuine relay out.
        for (const std::string& addr : {dialled, claim.advertise}) {
            if (addr.empty()) continue;
            auto known = peers_.find(addr);
            if (known && known->verified && !known->ed25519.empty() &&
                known->ed25519 != claim.ed25519) {
                log::warn("peer ", addr, " presented a key that contradicts its pin");
                send_error(s->conn, proto::kErrNotAuthorised, "node key does not match the pin");
                s->conn->close_now(1008, "key mismatch");
                return;
            }
        }

        if (!dialable(claim.advertise)) {
            log::warn("rejecting relay handshake on connection ", s->conn->id(),
                      ": advertised address ", claim.advertise, " is not publicly routable");
            send_error(s->conn, proto::kErrNotAuthorised, "advertise address is not public");
            s->conn->close_now(1008, "private advertise");
            return;
        }

        if (outbound && !dialled.empty()) {
            // We chose this address and the node answering there just proved
            // its key: that is what verification means.
            peers_.mark_ok(dialled, claim.node_id, claim.ed25519, claim.x25519);
            if (dialled != claim.advertise) {
                peers_.add(claim.advertise, false, false);
                peers_.learn_keys(claim.advertise, claim.node_id, claim.ed25519, claim.x25519);
            }
            drop_impostors(claim);
        } else {
            // An inbound relay may say it lives anywhere. Remember the claim so
            // the peer manager can dial it and find out; until then it is not
            // verified, not gossiped, not published and not a rendezvous node.
            peers_.add(claim.advertise, false, false);
            peers_.learn_keys(claim.advertise, claim.node_id, claim.ed25519, claim.x25519);
        }

        index_relay(s, claim);
        log::info("relay ", claim.advertise, " (", log::short_id(claim.node_id), ") is linked ",
                  s->conn->kind() == ConnKind::outbound_peer ? "outbound" : "inbound", " over ",
                  s->conn->secure() ? "wss" : "ws");

        if (!is_welcome) send_json(s->conn, identity_frame(proto::kWelcome));

        // Only the first handshake on a connection triggers a gossip exchange.
        // Without this, repeating `hello` would be a cheap amplifier: one frame
        // in, three out.
        bool first_time;
        {
            std::lock_guard<std::mutex> lock(mu_);
            first_time = !s->greeted;
            s->greeted = true;
        }
        if (cfg_.gossip_enabled && first_time) {
            handle_peers_req(s);
            send_json(s->conn, json{{"t", proto::kPeersReq}});
        }
        return;
    }

    // --- client -----------------------------------------------------------
    // Declaring an id binds this connection to a mailbox, so it has to be
    // proved. A client that declares nothing is anonymous: it may still send
    // to others, it simply cannot read anyone's mail.
    const std::string claimed = util::to_lower(util::trim(j.value("id", std::string{})));
    std::string id;
    if (!claimed.empty()) {
        auto proof = verify_client_proof(j);
        if (!proof.ok) {
            log::debug("rejected an unproved identity claim on connection ", s->conn->id());
            send_error(s->conn, proof.error,
                       "an id must be proved with pubkey, ts, nonce and sig");
            return;
        }
        id = proof.fingerprint;
        {
            std::lock_guard<std::mutex> lock(mu_);
            s->role = Role::client;
            s->identity = id;
            by_identity_.emplace(id, s->conn->id());
            last_seen_[id] = util::now_unix();
        }
        db_.touch_identity(id);
        // Wallets send their curve25519 public key alongside the ed25519
        // proof; stored so pointer contents can later be sealed to them.
        if (auto x = j.value("x25519", std::string{}); !x.empty()) {
            auto raw = util::b64_decode(x);
            if (raw && raw->size() == 32) db_.set_identity_x25519(id, x);
        }
        push_presence(id);
    } else {
        std::lock_guard<std::mutex> lock(mu_);
        s->role = Role::client;
    }

    json w = identity_frame(proto::kWelcome);
    w["you"] = id;
    w["pending"] = id.empty() ? 0 : db_.pending_for(id);
    w["ttl_days"] = cfg_.drop_ttl_days;
    w["max_payload"] = cfg_.max_payload_bytes;
    w["peers"] = peers_.verified_count();
    w["push"] = true;  // subscribe{push:true} delivers drops live
    if (!id.empty()) {
        const auto q = db_.quota_for(id);
        w["quota_bytes"] = q.max_bytes;
        w["used_bytes"] = q.used_bytes;
        // Tells the wallet whether to offer the relay-owner panel at all.
        w["owner"] = db_.owner_is(id);
    }
    if (cfg_.market_enabled()) {
        const std::int64_t pool = cfg_.pool_market_mb * 1024 * 1024;
        const std::int64_t committed = db_.rentals_committed_bytes();
        w["market"] = json{{"price_gb_epoch_micro", cfg_.market_price_micro},
                           {"available_bytes", pool > committed ? pool - committed : 0}};
    }
    send_json(s->conn, w);
}

// ----------------------------------------------------------- dead drops ----

bool Hub::store_locally(const std::string& msg_id, const std::string& recipient,
                        const util::Bytes& body, const std::string& from_hint,
                        const ConnectionPtr& reply_to, const std::string& home_hint) {
    const std::int64_t now = util::now_unix();
    const std::int64_t expires =
        now + db_.ttl_days_for(recipient, cfg_.drop_ttl_days) * 86400;

    std::int64_t seq = 0;
    const auto rc = db_.store_drop(msg_id, recipient, body.data(), body.size(), from_hint, now,
                                   expires, &seq);
    switch (rc) {
        case Db::StoreResult::ok:
            drops_accepted_.fetch_add(1, std::memory_order_relaxed);
            if (reply_to)
                send_json(reply_to, json{{"t", proto::kSent}, {"id", msg_id}, {"status", "stored"},
                                         {"expires_at", expires}});
            // Live delivery: sessions that subscribed with push get the drop
            // itself, exactly as a fetch would frame it. The row stays until
            // it is acked, so a missed push is redelivered by the next fetch.
            {
                std::vector<ConnectionPtr> push_to;
                {
                    std::lock_guard<std::mutex> lock(mu_);
                    auto range = by_identity_.equal_range(recipient);
                    for (auto it = range.first; it != range.second; ++it) {
                        auto sit = sessions_.find(it->second);
                        if (sit != sessions_.end() && sit->second->push)
                            push_to.push_back(sit->second->conn);
                    }
                }
                if (!push_to.empty()) {
                    json f{{"t", proto::kDrop},       {"id", msg_id},
                           {"seq", seq},              {"body", util::b64_encode(body)},
                           {"created_at", now},       {"expires_at", expires}};
                    if (!from_hint.empty()) f["hint"] = from_hint;
                    for (const auto& c : push_to) send_json(c, f);
                }
            }
            notify_recipient(recipient);
            // If the recipient's mailbox is elsewhere (or nowhere yet), tell
            // the network this relay is holding something for them.
            emit_pointer_if_remote(recipient, home_hint);
            return true;
        case Db::StoreResult::duplicate:
            if (reply_to)
                send_json(reply_to, json{{"t", proto::kSent}, {"id", msg_id},
                                         {"status", "duplicate"}});
            return true;
        case Db::StoreResult::quota_exceeded:
            drops_rejected_.fetch_add(1, std::memory_order_relaxed);
            if (reply_to)
                send_error(reply_to, proto::kErrQuota, "recipient mailbox is full", msg_id);
            return false;
        case Db::StoreResult::error:
        default:
            drops_rejected_.fetch_add(1, std::memory_order_relaxed);
            if (reply_to) send_error(reply_to, proto::kErrInternal, "could not store payload", msg_id);
            return false;
    }
}

constexpr std::size_t kPointerFanout = 3;
constexpr int kPointerHops = 4;

std::vector<std::string> Hub::rendezvous_addresses(const std::string& fp, std::size_t k,
                                                   bool* self_in_set) const {
    struct Ranked {
        std::string rank;
        std::string address;
        bool self;
    };
    std::vector<Ranked> pool;
    const std::string self = self_address();
    const auto rank_of = [&](const std::string& node_key) {
        return util::hex_encode(crypto::sha256("r2r-rdv-v1" + fp + node_key));
    };
    for (const auto& p : peers_.verified_peers()) {
        const std::string key = p.node_id.empty() ? p.address() : p.node_id;
        pool.push_back({rank_of(key), p.address(), false});
    }
    if (!self.empty()) pool.push_back({rank_of(node_.node_id()), self, true});

    std::sort(pool.begin(), pool.end(),
              [](const Ranked& a, const Ranked& b) { return a.rank < b.rank; });
    if (pool.size() > k) pool.resize(k);

    if (self_in_set) *self_in_set = false;
    std::vector<std::string> out;
    for (const auto& r : pool) {
        if (r.self) {
            if (self_in_set) *self_in_set = true;
        } else {
            out.push_back(r.address);
        }
    }
    return out;
}

void Hub::emit_pointer_if_remote(const std::string& recipient, const std::string& home_hint) {
    // Identities that live here, or are connected right now, collect their
    // mail here; no pointer needed.
    if (!connections_for(recipient).empty()) return;
    const std::string self = self_address();
    if (self.empty()) return;  // a relay nobody can dial has nothing to point at
    std::string home;
    if (auto h = db_.lookup_home_relay(recipient)) home = *h;
    const bool hinted = home.empty() && !home_hint.empty();
    if (hinted) home = home_hint;
    if (home == self) return;

    const std::int64_t ts = util::now_unix();
    auto sig = node_.sign(proto::pointer_signing_string(recipient, self, ts));
    if (!sig) return;
    json p{{"t", proto::kPointer},
           {"fp", recipient},
           {"address", self},
           {"count", db_.pending_for(recipient)},
           {"ts", ts},
           {"node_id", node_.node_id()},
           {"ed25519", node_.ed_pub_b64()},
           {"sig", util::b64_encode(*sig)},
           {"hops", kPointerHops}};
    const std::string frame = p.dump();

    // Straight to the home relay when it is known; otherwise the rendezvous
    // relays for this fingerprint, where its wallet knows to ask.
    // A home named only by the sender may be the very relay that was
    // unreachable, so the rendezvous set hears about it as well.
    std::vector<std::string> targets;
    if (!home.empty()) targets.push_back(home);
    if (home.empty() || hinted)
        for (auto& r : rendezvous_addresses(recipient, kPointerFanout, nullptr))
            if (std::find(targets.begin(), targets.end(), r) == targets.end()) targets.push_back(r);
    for (const auto& t : targets)
        if (t != self) route_to_relay(t, frame);
}

void Hub::handle_pointer(const SessionPtr& s, const json& j) {
    // send_error takes mu_ itself, so the role is read under the lock and
    // the reply goes out after it is released.
    bool is_relay;
    {
        std::lock_guard<std::mutex> lock(mu_);
        is_relay = s->role == Role::relay;
    }
    if (!is_relay) {
        send_error(s->conn, proto::kErrNotAuthorised, "pointers travel between relays");
        return;
    }
    // A pointer steers a wallet to a relay to gather mail, so it is accepted
    // only from a relay this node has verified (§11.2), and only about a
    // holder this node has verified: any key can sign a statement, but only
    // a relay found where it claims to be may be pointed at.
    if (!session_is_verified_relay(s)) {
        log::debug("pointer from an unverified relay session (", s->peer_address, ") dropped");
        return;
    }
    const std::string fp = util::to_lower(j.value("fp", std::string{}));
    const std::string sig_b64 = j.value("sig", std::string{});
    const std::string node_id = j.value("node_id", std::string{});
    const std::string ed_b64 = j.value("ed25519", std::string{});
    const std::int64_t ts = j.value("ts", std::int64_t{0});
    const std::int64_t count = std::max<std::int64_t>(0, j.value("count", std::int64_t{0}));
    const int hops = j.value("hops", 0);

    if (!util::is_valid_fingerprint(fp)) return;
    bool tls = false;
    auto canon = PeerRegistry::canonicalise(j.value("address", std::string{}), tls);
    if (!canon || *canon == self_address()) return;
    const std::int64_t now = util::now_unix();
    const std::int64_t max_age =
        static_cast<std::int64_t>(cfg_.drop_ttl_days) * 86400;
    if (ts > now + 600 || ts < now - max_age) return;

    // The statement must verify against the presented key, and that key must
    // be the pinned key of a verified peer at exactly the address pointed at.
    auto ed = util::b64_decode(ed_b64);
    auto sig = util::b64_decode(sig_b64);
    if (!ed || ed->size() != crypto::kPubLen || !sig) return;
    auto holder = peers_.find(*canon);
    if (!holder || !holder->verified || holder->node_id != node_id || holder->ed25519 != ed_b64) {
        log::debug("pointer for ", log::short_id(fp), " names ", *canon, " (node ",
                   log::short_id(node_id), "), which is not a relay this node has verified; dropped");
        return;
    }
    if (!crypto::verify_signature(*ed, proto::pointer_signing_string(fp, *canon, ts), *sig))
        return;

    if (!seen_.insert("p:" + fp + "|" + *canon + "|" + std::to_string(ts))) return;

    // Keep it if this identity is ours to answer for: homed here, connected
    // here, or this relay is in its rendezvous set.
    std::string home;
    if (auto h = db_.lookup_home_relay(fp)) home = *h;
    bool self_in_rdv = false;
    const auto rdv = rendezvous_addresses(fp, kPointerFanout, &self_in_rdv);
    const bool keep = home == self_address() || !connections_for(fp).empty() || self_in_rdv;

    if (keep) {
        const std::int64_t expires = std::min(ts + max_age, now + max_age);
        db_.pointer_store(fp, *canon, count, node_id, ed_b64, sig_b64, ts, expires);
        // A live session hears about it immediately.
        std::vector<ConnectionPtr> targets;
        {
            std::lock_guard<std::mutex> lock(mu_);
            auto range = by_identity_.equal_range(fp);
            for (auto it = range.first; it != range.second; ++it) {
                auto sit = sessions_.find(it->second);
                if (sit != sessions_.end() && sit->second->subscribed)
                    targets.push_back(sit->second->conn);
            }
        }
        for (const auto& c : targets)
            send_json(c, json{{"t", proto::kMailAt}, {"address", *canon}, {"count", count}});
        return;
    }

    if (hops <= 0) return;
    json fwd = j;
    fwd["hops"] = hops - 1;
    const std::string frame = fwd.dump();
    if (!home.empty()) {
        route_to_relay(home, frame);
        return;
    }
    for (const auto& t : rdv) route_to_relay(t, frame);
}

namespace {
constexpr int kCollectBatch = 200;
constexpr std::int64_t kAuthzMaxAgeSeconds = 7 * 86400;
bool valid_collect_scope(const std::string& s) {
    return s == "collect" || s == "collect-delete";
}
}  // namespace

void Hub::handle_deposit(const SessionPtr& s, const json& j) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        identity = s->identity;
    }
    if (identity.empty()) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return;
    }
    if (j.value("id", std::string{}) != identity) {
        send_error(s->conn, proto::kErrNotAuthorised, "deposit only your own mail");
        return;
    }
    const std::string pubkey = j.value("pubkey", std::string{});
    const std::string scope = j.value("scope", std::string("collect"));
    if (pubkey.empty() || !valid_collect_scope(scope) || !j.contains("targets") ||
        !j["targets"].is_array() || j["targets"].empty() || j["targets"].size() > 16) {
        send_error(s->conn, proto::kErrBadField,
                   "deposit needs pubkey, scope and 1..16 signed targets");
        return;
    }

    const std::int64_t now = util::now_unix();
    int sent = 0;
    for (const auto& t : j["targets"]) {
        if (!t.is_object()) continue;
        bool tls = false;
        auto canon = PeerRegistry::canonicalise(t.value("address", std::string{}), tls);
        if (!canon || *canon == self_address()) continue;
        json c{{"t", proto::kCollect},
               {"fp", identity},
               {"pubkey", pubkey},
               {"scope", scope},
               {"holder", *canon},
               {"ts", t.value("ts", std::int64_t{0})},
               {"nonce", t.value("nonce", std::string{})},
               {"sig", t.value("sig", std::string{})},
               {"want_max", kCollectBatch}};
        {
            std::lock_guard<std::mutex> lock(mu_);
            collecting_[identity + "|" + *canon] = now + 600;
        }
        if (route_to_relay(*canon, c.dump())) ++sent;
    }
    send_json(s->conn, json{{"t", proto::kDepositOk}, {"targets", sent}});
}

void Hub::handle_collect(const SessionPtr& s, const json& j) {
    bool is_relay;
    {
        std::lock_guard<std::mutex> lock(mu_);
        is_relay = s->role == Role::relay;
    }
    if (!is_relay) {
        send_error(s->conn, proto::kErrNotAuthorised, "collection is presented by relays");
        return;
    }
    // Only a relay this node has dialled and verified may present a
    // collection: the authorisation is the identity's, single-use and bound
    // to this holder, but the link it arrives on must be a real relay's, not
    // a session anyone could open with a key. The wallet re-deposits after
    // every connect and mail_at, so a collect dropped here is retried.
    if (!session_is_verified_relay(s)) {
        log::debug("collect from an unverified relay session (", s->peer_address, ") dropped");
        return;
    }
    const std::string fp = util::to_lower(j.value("fp", std::string{}));
    const std::string pub_b64 = j.value("pubkey", std::string{});
    const std::string scope = j.value("scope", std::string{});
    const std::string holder = j.value("holder", std::string{});
    const std::string nonce = j.value("nonce", std::string{});
    const std::string sig_b64 = j.value("sig", std::string{});
    const std::int64_t ts = j.value("ts", std::int64_t{0});

    if (!util::is_valid_fingerprint(fp) || !valid_collect_scope(scope) || nonce.size() < 16 ||
        nonce.size() > 64)
        return;
    // The instruction must name this relay; one signed for another holder is
    // meaningless here, and that binding is what makes capture useless.
    if (holder != self_address()) return;
    const std::int64_t now = util::now_unix();
    if (ts > now + 600 || ts < now - kAuthzMaxAgeSeconds) return;

    auto pub = util::b64_decode(pub_b64);
    auto sig = util::b64_decode(sig_b64);
    if (!pub || pub->size() != crypto::kPubLen || !sig) return;
    if (crypto::fingerprint(*pub) != fp) return;
    if (!crypto::verify_signature(*pub,
                                  proto::collect_signing_string(fp, holder, scope, ts, nonce),
                                  *sig))
        return;
    if (!db_.authz_burn(nonce)) {
        log::warn("collect for ", log::short_id(fp), " presented an already-used "
                  "authorization; refused");
        return;
    }

    auto drops = db_.fetch_drops(fp, 0, kCollectBatch);
    std::vector<std::string> sent_ids;
    for (const auto& d : drops) {
        json item{{"t", proto::kCollectItem},
                  {"fp", fp},
                  {"id", d.id},
                  {"body", util::b64_encode(d.payload)},
                  {"created_at", d.created_at}};
        if (!d.from_hint.empty()) item["hint"] = d.from_hint;
        send_json(s->conn, item);
        sent_ids.push_back(d.id);
    }
    send_json(s->conn, json{{"t", proto::kCollectDone},
                            {"fp", fp},
                            {"address", self_address()},
                            {"count", sent_ids.size()},
                            {"more", drops.size() == static_cast<std::size_t>(kCollectBatch)}});

    if (scope == "collect-delete" && !sent_ids.empty()) {
        const int removed = db_.delete_drops(fp, sent_ids);
        log::info("collected ", removed, " payloads for ", log::short_id(fp),
                  " and deleted them on this signed instruction");
    }
}

void Hub::handle_collect_item(const SessionPtr& s, const json& j) {
    std::string peer;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (s->role != Role::relay) return;
        peer = s->peer_address;
    }
    const std::string fp = util::to_lower(j.value("fp", std::string{}));
    // Only items this relay actually asked that peer for are accepted;
    // anything else would let a linked relay stuff arbitrary mailboxes.
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = collecting_.find(fp + "|" + peer);
        if (it == collecting_.end() || it->second < util::now_unix()) return;
    }
    const std::string msg_id = j.value("id", std::string{});
    if (!util::is_uuid_v4(msg_id)) return;
    auto body = util::b64_decode(j.value("body", std::string{}));
    if (!body || body->empty() || body->size() > cfg_.max_payload_bytes) return;
    std::string hint = j.value("hint", std::string{});
    if (hint.size() > 128) hint.clear();
    store_locally(msg_id, fp, *body, hint, nullptr);
}

void Hub::handle_collect_done(const SessionPtr& s, const json& j) {
    std::string peer;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (s->role != Role::relay) return;
        peer = s->peer_address;
    }
    const std::string fp = util::to_lower(j.value("fp", std::string{}));
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = collecting_.find(fp + "|" + peer);
        if (it == collecting_.end()) return;
        collecting_.erase(it);
    }
    // That holder's pointer is spent; a fresh one arrives if new mail lands.
    db_.pointer_delete(fp, peer);
    log::info("collection from ", peer, " for ", log::short_id(fp), " complete (",
              j.value("count", 0), " payloads",
              j.value("more", false) ? ", more remain" : "", ")");
}

void Hub::handle_locate(const SessionPtr& s) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        identity = s->identity;
    }
    if (identity.empty()) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return;
    }
    json arr = json::array();
    for (const auto& p : db_.pointers_for(identity))
        arr.push_back({{"address", p.address}, {"count", p.count}, {"ts", p.created_at}});
    send_json(s->conn, json{{"t", proto::kLocated},
                            {"pending", db_.pending_for(identity)},
                            {"pointers", std::move(arr)}});
}

void Hub::notify_recipient(const std::string& fingerprint) {
    std::vector<ConnectionPtr> targets;
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto range = by_identity_.equal_range(fingerprint);
        for (auto it = range.first; it != range.second; ++it) {
            auto sit = sessions_.find(it->second);
            if (sit != sessions_.end() && sit->second->subscribed) targets.push_back(sit->second->conn);
        }
    }
    if (targets.empty()) return;
    const std::int64_t pending = db_.pending_for(fingerprint);
    for (const auto& c : targets)
        send_json(c, json{{"t", proto::kMail}, {"pending", pending}});
}

void Hub::handle_send(const SessionPtr& s, const json& j) {
    Role role;
    {
        std::lock_guard<std::mutex> lock(mu_);
        role = s->role;
    }
    // Acknowledgements are for the originating client. Sending one back down a
    // relay link would be chatter the other node has no use for.
    const ConnectionPtr ack_to = (role == Role::relay) ? nullptr : s->conn;

    std::string msg_id = j.value("id", std::string{});
    if (msg_id.empty()) msg_id = crypto::uuid_v4();
    if (!util::is_uuid_v4(msg_id)) {
        send_error(s->conn, proto::kErrBadField, "id must be a v4 UUID");
        return;
    }

    if (!j.contains("to") || !j["to"].is_string()) {
        send_error(s->conn, proto::kErrBadField, "missing recipient", msg_id);
        return;
    }
    auto target = proto::parse_target(j["to"].get<std::string>());
    if (!target.valid) {
        send_error(s->conn, proto::kErrBadField, "recipient must be fp or fp@host:port", msg_id);
        return;
    }

    if (!j.contains("body") || !j["body"].is_string()) {
        send_error(s->conn, proto::kErrBadField, "missing body", msg_id);
        return;
    }
    auto body = util::b64_decode(j["body"].get<std::string>());
    if (!body || body->empty()) {
        send_error(s->conn, proto::kErrBadField, "body must be base64", msg_id);
        return;
    }
    if (body->size() > cfg_.max_payload_bytes) {
        send_error(s->conn, proto::kErrTooBig, "payload exceeds the relay limit", msg_id);
        return;
    }

    std::string hint = j.value("hint", std::string{});
    if (hint.size() > 128) hint.clear();

    if (!seen_.insert("m:" + msg_id)) {
        if (ack_to)
            send_json(ack_to, json{{"t", proto::kSent}, {"id", msg_id}, {"status", "duplicate"}});
        return;
    }

    // Where does this belong? An explicit @relay wins; otherwise consult the
    // identity's registered home relay; otherwise keep it here.
    std::string destination = target.relay;
    if (destination.empty()) {
        if (auto home = db_.lookup_home_relay(target.fingerprint)) destination = *home;
    }
    const bool local = destination.empty() || destination == self_address() ||
                       peers_.is_self(destination);

    if (local) {
        store_locally(msg_id, target.fingerprint, *body, hint, ack_to);
        return;
    }

    int hops = j.value("hops", cfg_.max_hops);
    if (hops <= 0) {
        send_error(s->conn, proto::kErrLooped, "hop limit reached", msg_id);
        return;
    }

    json fwd;
    fwd["t"] = proto::kSend;
    fwd["id"] = msg_id;
    fwd["to"] = target.fingerprint + "@" + destination;
    fwd["body"] = j["body"];
    if (!hint.empty()) fwd["hint"] = hint;
    fwd["hops"] = hops - 1;

    if (!route_to_relay(destination, fwd.dump())) {
        // Nowhere to forward it: hold it here so the message is not lost. The
        // recipient can still collect it by asking this relay directly.
        log::debug("no route to ", destination, "; holding the payload locally");
        store_locally(msg_id, target.fingerprint, *body, hint, ack_to);
        return;
    }
    forwarded_.fetch_add(1, std::memory_order_relaxed);
    if (ack_to)
        send_json(ack_to, json{{"t", proto::kSent}, {"id", msg_id}, {"status", "forwarded"},
                               {"via", destination}});
}

void Hub::handle_onion(const SessionPtr& s, const json& j) {
    if (!j.contains("blob") || !j["blob"].is_string()) {
        send_error(s->conn, proto::kErrBadField, "onion frame needs a blob");
        return;
    }
    auto blob = util::b64_decode(j["blob"].get<std::string>());
    if (!blob || blob->size() < crypto::kMultiMin || blob->size() > cfg_.max_frame_bytes) {
        send_error(s->conn, proto::kErrBadField, "blob is not a sealed layer");
        return;
    }

    int hops = j.value("hops", cfg_.max_hops);
    if (hops <= 0) {
        send_error(s->conn, proto::kErrLooped, "hop limit reached");
        return;
    }

    // Loop protection without learning anything about the route.
    if (!seen_.insert("o:" + digest_key(*blob))) return;

    auto plaintext = node_.unseal_multi(*blob);
    if (!plaintext) {
        send_error(s->conn, proto::kErrNoRoute, "this layer is not addressed to us");
        return;
    }
    auto layer = onion::parse(*plaintext, cfg_.max_payload_bytes);
    if (!layer) {
        send_error(s->conn, proto::kErrBadFrame, "malformed onion layer");
        return;
    }
    onion_peeled_.fetch_add(1, std::memory_order_relaxed);

    if (layer->terminal) {
        deliver_terminal(layer->deliver);
        return;
    }

    // Candidates for the next position, in the sender's order. This relay
    // may itself be listed (small networks reuse relays); it never forwards
    // to itself.
    std::vector<std::string> next;
    const std::string self = self_address();
    for (const auto& a : layer->next)
        if (a != self && !peers_.is_self(a)) next.push_back(a);
    if (next.empty()) {
        send_error(s->conn, proto::kErrNoRoute, "layer points back at this relay");
        return;
    }

    json fwd;
    fwd["t"] = proto::kOnion;
    fwd["blob"] = util::b64_encode(layer->inner);
    fwd["hops"] = hops - 1;
    if (!route_to_any(next, fwd.dump())) {
        log::debug("onion layer could not be forwarded: no candidate reachable");
        send_error(s->conn, proto::kErrNoRoute, "next hop is unreachable");
        return;
    }
    forwarded_.fetch_add(1, std::memory_order_relaxed);
}

// The end of an onion route. With no home named (or this relay being it) the
// payload is filed here. A terminal ALTERNATIVE -- the sender's fallback when
// the recipient's relay might be down -- forwards to that home as an ordinary
// send; if home stays unreachable the payload is parked here with a pointer.
void Hub::deliver_terminal(const onion::Terminal& d) {
    const std::string self = self_address();
    if (d.home.empty() || d.home == self || peers_.is_self(d.home)) {
        store_locally(d.msg_id, d.to, d.body, d.from_hint, nullptr);
        return;
    }
    if (!seen_.insert("m:" + d.msg_id)) return;
    json fwd{{"t", proto::kSend},
             {"id", d.msg_id},
             {"to", d.to + "@" + d.home},
             {"body", util::b64_encode(d.body)},
             {"hops", cfg_.max_hops}};
    if (!d.from_hint.empty()) fwd["hint"] = d.from_hint;
    if (!route_to_relay(d.home, fwd.dump())) store_locally(d.msg_id, d.to, d.body, d.from_hint, nullptr, d.home);
    else forwarded_.fetch_add(1, std::memory_order_relaxed);
}

void Hub::handle_fetch(const SessionPtr& s, const json& j) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        identity = s->identity;
    }
    if (identity.empty()) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return;
    }

    const std::int64_t since = j.value("since", std::int64_t{0});
    int limit = j.value("max", kFetchDefaultLimit);
    limit = std::clamp(limit, 1, kFetchMaxLimit);

    auto drops = db_.fetch_drops(identity, since, limit);
    for (const auto& d : drops) {
        json f;
        f["t"] = proto::kDrop;
        f["id"] = d.id;
        f["seq"] = d.seq;
        f["body"] = util::b64_encode(d.payload);
        if (!d.from_hint.empty()) f["hint"] = d.from_hint;
        f["created_at"] = d.created_at;
        f["expires_at"] = d.expires_at;
        send_json(s->conn, f);
    }

    const std::int64_t newest = drops.empty() ? since : drops.back().seq;
    {
        std::lock_guard<std::mutex> lock(mu_);
        s->last_fetch = util::now_unix();
    }
    send_json(s->conn, json{{"t", proto::kFetchDone},
                            {"count", drops.size()},
                            {"cursor", newest},
                            {"more", drops.size() == static_cast<std::size_t>(limit)}});
}

void Hub::handle_ack(const SessionPtr& s, const json& j) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        identity = s->identity;
    }
    if (identity.empty()) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return;
    }
    if (!j.contains("ids") || !j["ids"].is_array()) {
        send_error(s->conn, proto::kErrBadField, "ack needs an ids array");
        return;
    }
    std::vector<std::string> ids;
    for (const auto& v : j["ids"]) {
        if (!v.is_string()) continue;
        const std::string id = v.get<std::string>();
        if (util::is_uuid_v4(id)) ids.push_back(id);
        if (ids.size() >= 256) break;
    }
    const int removed = db_.ack_drops(identity, ids);
    // Received-and-acknowledged payloads are the traffic that activates a
    // member's invite codes. Only the recipient can ack, so this cannot be
    // inflated by anyone sending on their behalf without them reading it.
    if (removed > 0) {
        db_.note_received(identity, removed);
        if (const int n = db_.activate_if_ready(identity, proto::kActivationReceived))
            log::info("identity ", log::short_id(identity), " is active; ", n, " invite codes unlocked");
    }
    send_json(s->conn, json{{"t", "ack_ok"}, {"removed", removed}});
}

void Hub::handle_ping(const SessionPtr& s, const json& j) {
    json p{{"t", proto::kPong}, {"time", util::now_unix()}};
    if (j.contains("nonce") && j["nonce"].is_string()) p["nonce"] = j["nonce"];
    send_json(s->conn, p);
}

void Hub::handle_pong(const SessionPtr& s, const json&) {
    std::string address, dialled;
    {
        std::lock_guard<std::mutex> lock(mu_);
        address = s->peer_address;
        dialled = s->conn->dialled_address();
    }
    // Liveness only; a pong over an inbound link proves nothing about the
    // address the peer claimed, so it never verifies anything.
    if (!address.empty()) peers_.mark_alive(address);
    if (!dialled.empty() && dialled != address) peers_.mark_alive(dialled);
}

void Hub::drop_impostors(const PeerClaim& claim) {
    // The address just proved which key it belongs to. Any inbound session
    // that claimed the same address with a different key was squatting on it
    // to catch frames addressed there; it loses the address now.
    std::vector<ConnectionPtr> kick;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& [cid, sess] : sessions_) {
            if (sess->role != Role::relay || sess->peer_address != claim.advertise) continue;
            if (sess->node_id == claim.node_id) continue;
            kick.push_back(sess->conn);
        }
    }
    for (const auto& c : kick) {
        log::warn("closing a relay session that claimed ", claim.advertise,
                  " with a key the real node contradicts");
        c->close_now(1008, "address belongs to another key");
    }
}

void Hub::handle_peers_req(const SessionPtr& s) {
    if (!cfg_.gossip_enabled) return;
    auto entries = peers_.export_gossip(kMaxGossipEntries);
    json arr = json::array();
    for (const auto& e : entries) {
        json item{{"address", e.address}, {"tls", e.tls}};
        if (!e.node_id.empty()) item["node_id"] = e.node_id;
        if (!e.ed25519.empty()) item["ed25519"] = e.ed25519;
        if (!e.x25519.empty()) item["x25519"] = e.x25519;
        arr.push_back(std::move(item));
    }
    send_json(s->conn, json{{"t", proto::kPeers}, {"peers", std::move(arr)}});
}

void Hub::handle_peers(const SessionPtr& s, const json& j) {
    if (!cfg_.gossip_enabled) return;
    Role role;
    {
        std::lock_guard<std::mutex> lock(mu_);
        role = s->role;
    }
    // Only verified relays may grow the peer table; anonymous clients cannot.
    if (role != Role::relay) {
        send_error(s->conn, proto::kErrNotAuthorised, "only relays may gossip peers");
        return;
    }
    // ...and "relay" here means one this node has dialled and found where it
    // claims to be. A signed hello is enough to open a session, not enough to
    // steer whom this relay connects to next.
    if (!session_is_verified_relay(s)) {
        log::debug("ignoring a peer list from ", s->peer_address,
                   ": that relay has not been verified by dialling it yet");
        return;
    }
    if (!j.contains("peers") || !j["peers"].is_array()) return;

    std::vector<PeerRegistry::GossipEntry> entries;
    for (const auto& item : j["peers"]) {
        if (entries.size() >= kMaxGossipEntries) break;
        PeerRegistry::GossipEntry e;
        if (item.is_string()) {
            e.address = item.get<std::string>();
        } else if (item.is_object()) {
            e.address = item.value("address", std::string{});
            e.tls = item.value("tls", false);
            e.node_id = item.value("node_id", std::string{});
            e.ed25519 = item.value("ed25519", std::string{});
            e.x25519 = item.value("x25519", std::string{});
        }
        if (!e.address.empty()) entries.push_back(std::move(e));
    }
    std::size_t budget = 0;
    {
        std::lock_guard<std::mutex> lock(mu_);
        budget = s->gossip_new_left;
    }
    const std::size_t added = peers_.merge(entries, budget);
    {
        std::lock_guard<std::mutex> lock(mu_);
        s->gossip_new_left -= std::min(added, s->gossip_new_left);
    }
    if (added) log::info("gossip from ", s->peer_address, " added ", added, " new peers (table: ",
                         peers_.size(), ")");
}

bool Hub::session_is_verified_relay(const SessionPtr& s) const {
    std::string address, dialled;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (s->role != Role::relay) return false;
        address = s->peer_address;
        dialled = s->conn->dialled_address();
    }
    for (const std::string& a : {dialled, address}) {
        if (a.empty()) continue;
        if (auto p = peers_.find(a); p && p->verified) return true;
    }
    return false;
}

// ------------------------------------------------- calls and presence ------

std::vector<ConnectionPtr> Hub::connections_for(const std::string& fingerprint) const {
    std::vector<ConnectionPtr> out;
    std::lock_guard<std::mutex> lock(mu_);
    auto range = by_identity_.equal_range(fingerprint);
    for (auto it = range.first; it != range.second; ++it) {
        auto sit = sessions_.find(it->second);
        if (sit != sessions_.end()) out.push_back(sit->second->conn);
    }
    return out;
}

json Hub::presence_frame(const std::string& fingerprint) const {
    std::string state = "offline";
    std::int64_t seen = 0;
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto range = by_identity_.equal_range(fingerprint);
        for (auto it = range.first; it != range.second; ++it) {
            auto sit = sessions_.find(it->second);
            if (sit == sessions_.end()) continue;
            state = sit->second->presence_state;
            if (state == "online") break;  // any online session wins over away
        }
        auto ls = last_seen_.find(fingerprint);
        if (ls != last_seen_.end()) seen = ls->second;
    }
    return json{{"t", proto::kPresence}, {"id", fingerprint}, {"state", state}, {"seen", seen}};
}

void Hub::push_presence(const std::string& fingerprint) {
    std::vector<ConnectionPtr> targets;
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = watchers_.find(fingerprint);
        if (it == watchers_.end()) return;
        for (const auto& cid : it->second) {
            auto sit = sessions_.find(cid);
            if (sit != sessions_.end()) targets.push_back(sit->second->conn);
        }
    }
    if (targets.empty()) return;
    const std::string frame = presence_frame(fingerprint).dump();
    for (const auto& c : targets) c->send_text(frame);
}

void Hub::handle_watch(const SessionPtr& s, const json& j) {
    // Who is online is not public: an anonymous session could otherwise poll
    // any fingerprint's presence, which is the first step of steering a live
    // wallet somewhere. Proving a key costs the caller nothing but ties every
    // query to an identity.
    bool proved;
    {
        std::lock_guard<std::mutex> lock(mu_);
        proved = !s->identity.empty();
    }
    if (!proved) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return;
    }
    if (!j.contains("ids") || !j["ids"].is_array()) {
        send_error(s->conn, proto::kErrBadField, "watch needs an ids array");
        return;
    }
    std::vector<std::string> ids;
    for (const auto& v : j["ids"]) {
        if (!v.is_string()) continue;
        const std::string fp = util::to_lower(util::trim(v.get<std::string>()));
        if (util::is_valid_fingerprint(fp)) ids.push_back(fp);
        if (ids.size() >= kMaxWatchList) break;
    }
    {
        std::lock_guard<std::mutex> lock(mu_);
        const std::string& cid = s->conn->id();
        for (const auto& old : s->watching) {
            auto it = watchers_.find(old);
            if (it == watchers_.end()) continue;
            it->second.erase(cid);
            if (it->second.empty()) watchers_.erase(it);
        }
        s->watching.clear();
        for (const auto& fp : ids) {
            s->watching.insert(fp);
            watchers_[fp].insert(cid);
        }
    }
    for (const auto& fp : ids) send_json(s->conn, presence_frame(fp));
}

void Hub::handle_presence(const SessionPtr& s, const json& j) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        const std::string want = j.value("state", std::string{"online"});
        s->presence_state = (want == "away") ? "away" : "online";
        identity = s->identity;
    }
    if (!identity.empty()) push_presence(identity);
}

void Hub::handle_ice(const SessionPtr& s) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        identity = s->identity;
    }
    send_json(s->conn, json{{"t", proto::kIce},
                            {"iceServers", build_ice_servers(cfg_, identity)},
                            {"ttl", cfg_.ice_ttl_seconds}});
}

// Opaque WebRTC signalling. The relay carries offers, answers and ICE
// candidates between two clients and never looks inside; once they connect,
// the call itself is direct and the relay sees none of it.
void Hub::handle_sig(const SessionPtr& s, const json& j) {
    Role role;
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        role = s->role;
        identity = s->identity;
    }

    std::string from;
    if (role == Role::relay) {
        // Carried in from a peer relay, which vouched for it with its own
        // signed handshake.
        from = util::to_lower(util::trim(j.value("from", std::string{})));
        if (!util::is_valid_fingerprint(from)) return;
    } else {
        from = identity;
        if (from.empty()) {
            send_error(s->conn, proto::kErrNotAuthorised, "prove your id before signalling");
            return;
        }
    }

    if (!j.contains("to") || !j["to"].is_string() || !j.contains("body") ||
        !j["body"].is_string()) {
        send_error(s->conn, proto::kErrBadField, "sig needs to and body");
        return;
    }
    auto target = proto::parse_target(j["to"].get<std::string>());
    if (!target.valid) {
        send_error(s->conn, proto::kErrBadField, "sig recipient is malformed");
        return;
    }
    const std::string body = j["body"].get<std::string>();
    if (body.size() > cfg_.max_payload_bytes) {
        send_error(s->conn, proto::kErrTooBig, "signalling payload is too large");
        return;
    }

    std::string destination = target.relay;
    if (destination.empty()) {
        if (auto home = db_.lookup_home_relay(target.fingerprint)) destination = *home;
    }
    const bool local =
        destination.empty() || destination == self_address() || peers_.is_self(destination);

    if (local) {
        auto conns = connections_for(target.fingerprint);
        if (conns.empty()) {
            // Calls are live: there is nothing useful to store for later.
            send_error(s->conn, proto::kErrNotOnline, "that peer is not connected");
            return;
        }
        json out{{"t", proto::kSig}, {"from", from}, {"body", body}};
        if (j.contains("call") && j["call"].is_string()) out["call"] = j["call"];
        const std::string frame = out.dump();
        for (const auto& c : conns) c->send_text(frame);
        frames_out_.fetch_add(static_cast<std::int64_t>(conns.size()), std::memory_order_relaxed);
        return;
    }

    int hops = j.value("hops", cfg_.max_hops);
    if (hops <= 0) {
        send_error(s->conn, proto::kErrLooped, "hop limit reached");
        return;
    }
    json fwd{{"t", proto::kSig},
             {"from", from},
             {"to", target.fingerprint + "@" + destination},
             {"body", body},
             {"hops", hops - 1}};
    if (j.contains("call") && j["call"].is_string()) fwd["call"] = j["call"];
    if (!route_to_relay(destination, fwd.dump()))
        send_error(s->conn, proto::kErrNoRoute, "no route to that peer's relay");
    else
        forwarded_.fetch_add(1, std::memory_order_relaxed);
}

// ------------------------------------------------------------ journal ------

void Hub::handle_journal_append(const SessionPtr& s, const json& j) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        identity = s->identity;
    }
    if (identity.empty()) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return;
    }
    if (!j.contains("data") || !j["data"].is_string()) {
        send_error(s->conn, proto::kErrBadField, "journal_append needs base64 data");
        return;
    }
    auto data = util::b64_decode(j["data"].get<std::string>());
    if (!data || data->empty()) {
        send_error(s->conn, proto::kErrBadField, "data must be base64");
        return;
    }
    if (data->size() > cfg_.max_journal_entry_bytes) {
        send_error(s->conn, proto::kErrTooBig, "journal entry is too large");
        return;
    }

    std::int64_t seq = 0;
    switch (db_.journal_append(identity, data->data(), data->size(), seq)) {
        case Db::AppendResult::ok:
            send_json(s->conn, json{{"t", proto::kJournalOk}, {"seq", seq}});
            return;
        case Db::AppendResult::quota_exceeded:
            send_error(s->conn, proto::kErrQuota, "storage allowance is full");
            return;
        default:
            send_error(s->conn, proto::kErrInternal, "could not write the journal entry");
            return;
    }
}

void Hub::handle_journal_read(const SessionPtr& s, const json& j) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        identity = s->identity;
    }
    if (identity.empty()) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return;
    }
    const std::int64_t since = j.value("since", std::int64_t{0});
    int limit = j.value("max", cfg_.journal_read_limit);
    limit = std::clamp(limit, 1, cfg_.journal_read_limit);

    bool truncated = false;
    auto entries = db_.journal_read(identity, since, limit, cfg_.journal_read_bytes, &truncated);
    json arr = json::array();
    for (const auto& e : entries)
        arr.push_back({{"seq", e.seq},
                       {"data", util::b64_encode(e.data)},
                       {"created_at", e.created_at}});

    const std::int64_t cursor = entries.empty() ? since : entries.back().seq;
    send_json(s->conn, json{{"t", proto::kJournal},
                            {"entries", std::move(arr)},
                            {"cursor", cursor},
                            {"more", truncated ||
                                         entries.size() == static_cast<std::size_t>(limit)}});
}

// -------------------------------------------------- relay administration ---

std::string Hub::require_owner(const SessionPtr& s) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        identity = s->identity;
    }
    if (identity.empty()) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return {};
    }
    if (!db_.owner_is(identity)) {
        // Deliberately the same answer either way: whether a given fingerprint
        // owns this relay is not something an arbitrary client should learn.
        send_error(s->conn, proto::kErrNotAuthorised, "not an owner of this relay");
        return {};
    }
    return identity;
}

// ------------------------------------------------------ storage market -----

namespace {
bool evm_address_ok(const std::string& a) {
    if (a.size() != 42 || a[0] != '0' || a[1] != 'x') return false;
    for (std::size_t i = 2; i < a.size(); ++i)
        if (!std::isxdigit(static_cast<unsigned char>(a[i]))) return false;
    return true;
}
// micro-USDC for `bytes` at `price` per GB-epoch, rounded up, overflow-safe.
std::int64_t epoch_price_micro(std::int64_t bytes, std::int64_t price) {
    constexpr std::int64_t kGiB = 1024LL * 1024 * 1024;
    const std::int64_t whole = bytes / kGiB;
    const std::int64_t rest = bytes % kGiB;
    return whole * price + (rest * price + kGiB - 1) / kGiB;
}
}  // namespace

void Hub::handle_rent(const SessionPtr& s, const json& j) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        identity = s->identity;
    }
    if (identity.empty()) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return;
    }
    if (!cfg_.market_enabled()) {
        send_error(s->conn, proto::kErrMarketOff, "this relay does not sell storage");
        return;
    }
    const std::int64_t bytes = j.value("bytes", std::int64_t{0});
    const std::int64_t pool = cfg_.pool_market_mb * 1024 * 1024;
    if (bytes < 1024 * 1024 || bytes > pool) {
        send_error(s->conn, proto::kErrBadField, "bytes must be between 1 MB and the market pool");
        return;
    }
    const std::string payment_key = util::to_lower(util::trim(j.value("payment_key", std::string{})));
    if (!evm_address_ok(payment_key)) {
        send_error(s->conn, proto::kErrBadField, "payment_key must be a 0x… address");
        return;
    }

    // Reservations, never hope: what is committed is subtracted from what can
    // be sold, so the pool cannot be promised twice.
    const std::int64_t committed = db_.rentals_committed_bytes();
    if (committed + bytes > pool) {
        send_error(s->conn, proto::kErrMarketFull, "not enough free market storage");
        return;
    }

    Db::Rental r;
    r.id = crypto::uuid_v4();
    r.fingerprint = identity;
    r.bytes = bytes;
    r.price_micro = epoch_price_micro(bytes, cfg_.market_price_micro);
    r.payment_key = payment_key;
    r.created_at = util::now_unix();
    // The first epoch runs on trust (grace); the first voucher extends it.
    // A renter who never pays costs at most one epoch of one slice.
    r.paid_until = r.created_at + std::int64_t{cfg_.rent_grace_days} * 86400;
    if (!db_.rental_create(r)) {
        send_error(s->conn, proto::kErrInternal, "could not record the rental");
        return;
    }
    log::info("rented ", bytes, " bytes to ", log::short_id(identity), " for ",
              r.price_micro, " micro-USDC/epoch (", committed + bytes, "/", pool,
              " committed)");
    send_json(s->conn, json{{"t", proto::kRentOk},
                            {"rental", r.id},
                            {"bytes", r.bytes},
                            {"price_epoch_micro", r.price_micro},
                            {"epoch_days", cfg_.rent_epoch_days},
                            {"paid_until", r.paid_until},
                            {"payout", cfg_.payout_address},
                            {"vault", cfg_.vault_address},
                            {"chain_id", cfg_.chain_id}});
}

void Hub::handle_voucher(const SessionPtr& s, const json& j) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        identity = s->identity;
    }
    if (identity.empty()) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return;
    }
    if (!cfg_.market_enabled()) {
        send_error(s->conn, proto::kErrMarketOff, "this relay does not sell storage");
        return;
    }
    const std::string rental_id = j.value("rental", std::string{});
    auto rental = db_.rental_get(rental_id);
    if (!rental || rental->fingerprint != identity) {
        send_error(s->conn, proto::kErrBadField, "no such rental of yours");
        return;
    }
    const std::string payment_key = util::to_lower(util::trim(j.value("payment_key", std::string{})));
    const std::string payout = util::to_lower(util::trim(j.value("payout", std::string{})));
    if (!evm_address_ok(payment_key) || payout != util::to_lower(cfg_.payout_address)) {
        send_error(s->conn, proto::kErrBadField,
                   "payment_key must be an address and payout must be this relay's");
        return;
    }
    if (payment_key != rental->payment_key) {
        send_error(s->conn, proto::kErrBadField, "payment_key is not the one this rental was opened with",
                   rental_id);
        return;
    }
    const std::int64_t cumulative = j.value("cumulative_micro", std::int64_t{0});
    const std::string sig = util::to_lower(util::trim(j.value("sig", std::string{})));
    // 65-byte EIP-191 signature as 0x + 130 hex.
    if (sig.size() != 132 || sig.rfind("0x", 0) != 0 || cumulative <= 0) {
        send_error(s->conn, proto::kErrBadField, "voucher needs cumulative_micro and a 65-byte sig");
        return;
    }
    // The signature is checked here, before any storage is granted on its
    // strength: the same recovery the vault performs at redemption, over the
    // §14.4 digest, and the signer must be the rental's payment key. Storage
    // was handed over on unverified vouchers once, and garbage bought months.
    if (cfg_.vault_address.empty()) {
        send_error(s->conn, proto::kErrMarketOff,
                   "this relay cannot verify vouchers: it has no --vault-address");
        return;
    }
    const crypto::Bytes digest =
        crypto::evm_voucher_digest(cfg_.vault_address, cfg_.chain_id, payout, cumulative);
    auto sig_bytes = util::hex_decode(std::string_view(sig).substr(2));
    std::optional<std::string> signer;
    if (!digest.empty() && sig_bytes) signer = crypto::evm_recover_address(digest, *sig_bytes);
    if (!signer || *signer != payment_key) {
        log::warn("voucher from ", log::short_id(identity), " for rental ", rental_id,
                  " does not verify against payment key ", payment_key, "; refused");
        send_error(s->conn, proto::kErrNotAuthorised, "voucher signature does not match the payment key",
                   rental_id);
        return;
    }

    std::int64_t prev = 0;
    if (!db_.voucher_store(payment_key, payout, cumulative, sig, j.dump(), &prev)) {
        send_error(s->conn, proto::kErrBadField, "voucher must exceed the previous cumulative",
                   rental_id);
        return;
    }
    if (cumulative - prev < rental->price_micro) {
        // The voucher is kept (it is still the best money seen) but buys no
        // extension until the cumulative covers a full epoch.
        send_error(s->conn, proto::kErrBadField,
                   "cumulative must rise by at least the rental's epoch price", rental_id);
        return;
    }
    const std::int64_t paid_until =
        db_.rental_renew(rental_id, identity, std::int64_t{cfg_.rent_epoch_days} * 86400,
                         3 * std::int64_t{cfg_.rent_epoch_days} * 86400);
    if (paid_until == 0) {
        send_error(s->conn, proto::kErrInternal, "could not extend the rental");
        return;
    }
    log::info("voucher from ", log::short_id(identity), ": ", cumulative,
              " micro-USDC cumulative (+", cumulative - prev, "), rental ", rental_id,
              " paid until ", paid_until);
    send_json(s->conn, json{{"t", proto::kVoucherOk},
                            {"rental", rental_id},
                            {"paid_until", paid_until},
                            {"cumulative_micro", cumulative}});
}

void Hub::handle_admin_list_rentals(const SessionPtr& s) {
    const std::string owner = require_owner(s);
    if (owner.empty()) return;
    json rows = json::array();
    for (const auto& r : db_.rentals_list(500)) {
        rows.push_back(json{{"id", r.id},
                            {"fingerprint", r.fingerprint},
                            {"bytes", r.bytes},
                            {"price_epoch_micro", r.price_micro},
                            {"payment_key", r.payment_key},
                            {"created_at", r.created_at},
                            {"paid_until", r.paid_until},
                            {"state", r.state}});
    }
    const std::int64_t pool = cfg_.pool_market_mb * 1024 * 1024;
    send_json(s->conn, json{{"t", proto::kAdminOk},
                            {"action", "list_rentals"},
                            {"rentals", rows},
                            {"committed_bytes", db_.rentals_committed_bytes()},
                            {"pool_bytes", pool}});
}

void Hub::handle_admin_list_vouchers(const SessionPtr& s) {
    const std::string owner = require_owner(s);
    if (owner.empty()) return;
    // The settlement export: the newest voucher per payer, ready for the
    // operator's browser wallet to redeem against the vault. No chain keys
    // ever touch the relay.
    json rows = json::array();
    std::int64_t total = 0;
    for (const auto& v : db_.vouchers_latest()) {
        rows.push_back(json{{"payment_key", v.payment_key},
                            {"payout", v.payout},
                            {"cumulative_micro", v.cumulative_micro},
                            {"sig", v.sig},
                            {"created_at", v.created_at}});
        total += v.cumulative_micro;
    }
    send_json(s->conn, json{{"t", proto::kAdminOk},
                            {"action", "list_vouchers"},
                            {"vouchers", rows},
                            {"cumulative_total_micro", total},
                            {"payout", cfg_.payout_address},
                            {"vault", cfg_.vault_address},
                            {"chain_id", cfg_.chain_id}});
}

void Hub::handle_admin_accounts(const SessionPtr& s, const json& j) {
    if (require_owner(s).empty()) return;

    int limit = std::clamp(j.value("max", 100), 1, 500);
    const int offset = std::max(0, j.value("offset", 0));
    auto accounts = db_.list_accounts(limit, offset);

    json arr = json::array();
    for (const auto& a : accounts) {
        auto pending = db_.pending_for(a.fingerprint);
        arr.push_back({{"id", a.fingerprint},
                       {"home_relay", a.home_relay},
                       {"registered_at", a.registered_at},
                       {"last_seen", a.last_seen},
                       {"used_bytes", a.used_bytes},
                       {"quota_bytes", a.quota_bytes},
                       {"custom_quota", a.custom_quota},
                       {"pending", pending},
                       {"online", !connections_for(a.fingerprint).empty()}});
    }
    send_json(s->conn, json{{"t", proto::kAdminAccounts},
                            {"accounts", std::move(arr)},
                            {"offset", offset},
                            {"default_quota_bytes",
                             static_cast<std::int64_t>(cfg_.default_quota_mb) * 1024 * 1024}});
}

void Hub::handle_admin_set_quota(const SessionPtr& s, const json& j) {
    const std::string owner = require_owner(s);
    if (owner.empty()) return;

    const std::string target = util::to_lower(util::trim(j.value("id", std::string{})));
    if (!util::is_valid_fingerprint(target)) {
        send_error(s->conn, proto::kErrBadField, "id must be a hex fingerprint");
        return;
    }
    if (!j.contains("mb")) {
        send_error(s->conn, proto::kErrBadField, "set an mb value, or null to use the default");
        return;
    }

    bool ok;
    if (j["mb"].is_null()) {
        ok = db_.clear_quota(target);
    } else {
        const std::int64_t mb = j.value("mb", std::int64_t{0});
        if (mb < 0 || mb > 1024 * 1024) {
            send_error(s->conn, proto::kErrBadField, "mb must be between 0 and 1048576");
            return;
        }
        ok = db_.set_quota_bytes(target, mb * 1024 * 1024);
    }
    if (!ok) {
        send_error(s->conn, proto::kErrInternal, "could not change the allowance");
        return;
    }

    const auto q = db_.quota_for(target);
    log::info("owner ", log::short_id(owner), " set the allowance for ",
              log::short_id(target), " to ", q.max_bytes, " bytes");
    send_json(s->conn, json{{"t", proto::kAdminOk},
                            {"action", "set_quota"},
                            {"id", target},
                            {"quota_bytes", q.max_bytes},
                            {"used_bytes", q.used_bytes},
                            {"custom", q.custom}});
}

void Hub::handle_admin_invites(const SessionPtr& s, const json& j) {
    const std::string owner = require_owner(s);
    if (owner.empty()) return;

    std::string hint;
    if (auto addr = util::parse_address(self_address(), cfg_.ws_port))
        hint = util::ipv4_hint_hex(addr->host);

    const int count = std::clamp(j.value("count", 3), 1, 50);
    auto codes = db_.mint_invites(count, owner, hint);
    if (codes.empty()) {
        send_error(s->conn, proto::kErrInternal, "could not mint invite codes");
        return;
    }
    log::info("owner ", log::short_id(owner), " minted ", codes.size(), " invite codes");
    send_json(s->conn, json{{"t", proto::kAdminInvites}, {"invites", codes}});
}

void Hub::handle_admin_revoke_invite(const SessionPtr& s, const json& j) {
    const std::string owner = require_owner(s);
    if (owner.empty()) return;

    const std::string code = util::normalize_invite_code(j.value("code", std::string{}));
    if (code.empty()) {
        send_error(s->conn, proto::kErrBadField, "code is not a valid invite code");
        return;
    }
    const bool cascade = j.value("cascade", true);
    const auto r = db_.revoke_invite(code, cascade, owner);
    if (!r.found) {
        send_error(s->conn, proto::kErrInviteInvalid, "no such invite code");
        return;
    }
    log::info("owner ", log::short_id(owner), " revoked invite ", code, " (",
              r.direct, " direct, ", r.cascaded, " cascaded)");
    send_json(s->conn, json{{"t", proto::kAdminOk},
                            {"action", "revoke_invite"},
                            {"code", code},
                            {"revoked", r.direct},
                            {"cascaded", r.cascaded}});
}

void Hub::handle_admin_list_invites(const SessionPtr& s, const json& j) {
    if (require_owner(s).empty()) return;

    const int limit = std::clamp(j.value("max", 100), 1, 500);
    const int offset = std::max(0, j.value("offset", 0));
    std::string state = j.value("state", std::string("all"));
    if (state != "open" && state != "burned" && state != "revoked" && state != "locked") state = "all";

    auto rows = db_.list_invites(limit, offset, state);
    json arr = json::array();
    for (const auto& r : rows) {
        json item{{"code", r.code},
                  {"created_at", r.created_at},
                  {"issued_by", r.issued_by},
                  {"state", r.state},
                  {"has_contact_token", r.has_contact_token}};
        if (!r.parent_code.empty()) item["parent_code"] = r.parent_code;
        if (r.state == "burned") {
            item["burned_at"] = r.burned_at;
            item["burned_by"] = r.burned_by;
        }
        if (r.state == "revoked") {
            item["revoked_at"] = r.revoked_at;
            item["revoked_by"] = r.revoked_by;
        }
        arr.push_back(std::move(item));
    }
    send_json(s->conn, json{{"t", proto::kAdminListInvites},
                            {"invites", std::move(arr)},
                            {"offset", offset},
                            {"state", state}});
}

void Hub::handle_admin_set_ttl(const SessionPtr& s, const json& j) {
    const std::string owner = require_owner(s);
    if (owner.empty()) return;

    const std::string target = util::to_lower(util::trim(j.value("id", std::string{})));
    if (!util::is_valid_fingerprint(target)) {
        send_error(s->conn, proto::kErrBadField, "id must be a hex fingerprint");
        return;
    }
    if (!j.contains("days")) {
        send_error(s->conn, proto::kErrBadField,
                   "set a days value (-1 = keep forever), or null for the default");
        return;
    }

    bool ok;
    if (j["days"].is_null()) {
        ok = db_.clear_account_ttl(target);
    } else {
        const std::int64_t days = j.value("days", std::int64_t{0});
        if (days < -1 || days == 0 || days > 36500) {
            send_error(s->conn, proto::kErrBadField, "days must be -1 or 1..36500");
            return;
        }
        ok = db_.set_account_ttl(target, days);
    }
    if (!ok) {
        send_error(s->conn, proto::kErrInternal, "could not change the retention");
        return;
    }
    log::info("owner ", log::short_id(owner), " set retention for ", log::short_id(target));
    send_json(s->conn, json{{"t", proto::kAdminOk},
                            {"action", "set_ttl"},
                            {"id", target},
                            {"ttl_days", db_.ttl_days_for(target, cfg_.drop_ttl_days)}});
}

void Hub::handle_admin_search_accounts(const SessionPtr& s, const json& j) {
    if (require_owner(s).empty()) return;

    const std::string q = util::to_lower(util::trim(j.value("q", std::string{})));
    if (q.empty() || q.size() > 128) {
        send_error(s->conn, proto::kErrBadField, "q must be a fingerprint prefix or relay text");
        return;
    }
    const int limit = std::clamp(j.value("max", 50), 1, 200);
    auto accounts = db_.search_accounts(q, limit);
    json arr = json::array();
    for (const auto& a : accounts) {
        arr.push_back({{"id", a.fingerprint},
                       {"home_relay", a.home_relay},
                       {"registered_at", a.registered_at},
                       {"last_seen", a.last_seen},
                       {"used_bytes", a.used_bytes},
                       {"quota_bytes", a.quota_bytes},
                       {"custom_quota", a.custom_quota},
                       {"pending", db_.pending_for(a.fingerprint)},
                       {"online", !connections_for(a.fingerprint).empty()}});
    }
    send_json(s->conn, json{{"t", proto::kAdminSearchAccounts},
                            {"accounts", std::move(arr)},
                            {"q", q}});
}

void Hub::handle_admin_delete_account(const SessionPtr& s, const json& j) {
    const std::string owner = require_owner(s);
    if (owner.empty()) return;

    const std::string target = util::to_lower(util::trim(j.value("id", std::string{})));
    if (!util::is_valid_fingerprint(target)) {
        send_error(s->conn, proto::kErrBadField, "id must be a hex fingerprint");
        return;
    }
    if (db_.owner_is(target)) {
        // Removing an owner is a deliberate host-side act (--owner-remove),
        // not something one owner does to another from a wallet.
        send_error(s->conn, proto::kErrNotAuthorised, "target is a relay owner");
        return;
    }

    const auto r = db_.delete_account(target);
    if (!r.ok) {
        send_error(s->conn, proto::kErrInternal, "could not delete the account");
        return;
    }
    if (blobs_)
        for (const auto& id : r.orphaned_blob_ids) blobs_->remove(id);

    // Close any live sessions the deleted identity still has.
    for (const auto& c : connections_for(target)) c->close_now(1008, "account deleted");

    log::info("owner ", log::short_id(owner), " deleted account ", log::short_id(target), " (",
              r.drops, " drops, ", r.journal, " journal entries, ", r.blobs, " blob refs)");
    send_json(s->conn, json{{"t", proto::kAdminOk},
                            {"action", "delete_account"},
                            {"id", target},
                            {"drops_removed", r.drops},
                            {"journal_removed", r.journal},
                            {"blobs_removed", r.blobs}});
}

void Hub::handle_admin_set_advertise(const SessionPtr& s, const json& j) {
    const std::string owner = require_owner(s);
    if (owner.empty()) return;

    const std::string host = util::trim(j.value("host", std::string{}));
    bool tls = false;
    auto canon = PeerRegistry::canonicalise(host, tls);
    if (host.empty() || !canon) {
        send_error(s->conn, proto::kErrBadField, "host must look like host or host:port");
        return;
    }
    if (!set_advertise(*canon)) {
        send_error(s->conn, proto::kErrInternal, "could not apply the new address");
        return;
    }
    log::info("owner ", log::short_id(owner), " changed the advertised address to ", *canon);
    send_json(s->conn, json{{"t", proto::kAdminOk},
                            {"action", "set_advertise"},
                            {"advertise", *canon}});
}

bool Hub::set_advertise(const std::string& canonical) {
    {
        std::lock_guard<std::mutex> lock(addr_mu_);
        self_address_ = canonical;
    }
    peers_.set_self(canonical, node_.node_id(), node_.ed_pub_b64(), node_.x_pub_b64());
    // Persisted so a restart keeps the operator's choice; startup prefers this
    // over the environment when present.
    db_.meta_set("advertise_override", canonical);
    if (advertise_hook_) advertise_hook_(canonical);
    return true;
}

void Hub::handle_quota(const SessionPtr& s) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        identity = s->identity;
    }
    if (identity.empty()) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return;
    }
    const auto q = db_.quota_for(identity);
    send_json(s->conn, json{{"t", proto::kQuota},
                            {"quota_bytes", q.max_bytes},
                            {"used_bytes", q.used_bytes},
                            {"used_payloads", q.used_drops},
                            {"max_payloads", q.max_drops},
                            {"custom", q.custom}});
}

void Hub::handle_subscribe(const SessionPtr& s, const json& j) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        s->subscribed = true;
        s->push = j.value("push", false);
        identity = s->identity;
    }
    if (identity.empty()) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return;
    }
    send_json(s->conn, json{{"t", proto::kMail}, {"pending", db_.pending_for(identity)}});
}

// -------------------------------------------------------------- invites ----

Hub::ClaimOutcome Hub::claim_invite(const json& req) {
    ClaimOutcome out;
    const std::string code = util::normalize_invite_code(req.value("code", std::string{}));
    if (cfg_.require_invite && code.empty()) {
        out.error = proto::kErrInviteInvalid;
        return out;
    }

    // Without this, anyone could register their own relay as the home of
    // someone else's fingerprint and have that person's mail routed to them.
    auto proof = verify_client_proof(req);
    if (!proof.ok) {
        out.error = proof.error;
        return out;
    }
    const std::string fp = proof.fingerprint;

    std::string home = util::trim(req.value("home_relay", std::string{}));
    if (!home.empty()) {
        bool tls = false;
        auto canon = PeerRegistry::canonicalise(home, tls);
        if (!canon) {
            out.error = proto::kErrBadField;
            return out;
        }
        home = *canon;
    } else {
        home = self_address();
    }

    const std::string key = proof.pubkey_b64;

    // Codes minted here carry this relay's IPv4 as a routing hint when the
    // advertise address allows it, so a code redeemed on the wrong relay can
    // be redirected home.
    std::string hint;
    if (auto addr = util::parse_address(self_address(), cfg_.ws_port))
        hint = util::ipv4_hint_hex(addr->host);

    // Open registration: no code to burn, but the identity is still recorded
    // and the caller still receives three codes, so one client works against
    // either kind of relay.
    if (!cfg_.require_invite) {
        if (db_.identity_exists(fp)) {
            out.error = proto::kErrAlreadyRegistered;
            return out;
        }
        if (!db_.register_identity(fp, home, key)) {
            out.error = proto::kErrInternal;
            return out;
        }
        out.invites = db_.mint_invites(kInvitesPerClaim, fp, hint, {}, /*locked=*/true);
        out.locked = true;
        out.ok = true;
        return out;
    }

    std::vector<std::string> codes;
    switch (db_.claim_invite(code, fp, home, key, kInvitesPerClaim, hint, codes)) {
        case Db::ClaimResult::ok:
            invites_burned_.fetch_add(1, std::memory_order_relaxed);
            log::info("invite burned; identity ", log::short_id(fp), " now homed at ",
                      home.empty() ? "this relay" : home);
            out.ok = true;
            out.invites = std::move(codes);
            out.locked = true;
            {
                const auto a = db_.activation(fp, proto::kActivationReceived);
                out.inviter = a.inviter;
                out.inviter_pubkey = a.inviter_pubkey;
            }
            return out;
        case Db::ClaimResult::locked:
            out.error = proto::kErrInviteLocked;
            return out;
        case Db::ClaimResult::already_registered:
            out.error = proto::kErrAlreadyRegistered;
            return out;
        case Db::ClaimResult::already_used:
            out.error = proto::kErrInviteUsed;
            return out;
        case Db::ClaimResult::revoked:
            out.error = proto::kErrInviteRevoked;
            return out;
        case Db::ClaimResult::not_found:
            out.error = proto::kErrInviteInvalid;
            return out;
        default:
            out.error = proto::kErrInternal;
            return out;
    }
}

void Hub::handle_invite_claim(const SessionPtr& s, const json& j) {
    auto outcome = claim_invite(j);
    if (!outcome.ok) {
        send_error(s->conn, outcome.error, "invite could not be claimed");
        return;
    }
    if (auto x = j.value("x25519", std::string{}); !x.empty()) {
        auto raw = util::b64_decode(x);
        if (raw && raw->size() == 32) {
            const std::string fp = util::to_lower(util::trim(j.value("id", std::string{})));
            if (util::is_valid_fingerprint(fp)) db_.set_identity_x25519(fp, x);
        }
    }
    json ok{{"t", proto::kInviteOk},
            {"invites", outcome.invites},
            {"locked", outcome.locked},
            {"home_relay", self_address()},
            {"node_id", node_.node_id()},
            {"unlock", {{"received_needed", proto::kActivationReceived},
                        {"vouch_needed", !outcome.inviter.empty()}}}};
    if (!outcome.inviter.empty())
        ok["inviter"] = {{"id", outcome.inviter}, {"pubkey", outcome.inviter_pubkey}};
    send_json(s->conn, ok);
}

json Hub::activation_json(const std::string& fp) {
    const auto a = db_.activation(fp, proto::kActivationReceived);
    json invites = json::array();
    for (const auto& i : db_.invites_issued_by(fp))
        invites.push_back({{"code", i.code}, {"state", i.state}});
    json j{{"t", proto::kInviteStatus},
           {"registered", a.registered},
           {"active", a.active},
           {"received", a.received},
           {"received_needed", proto::kActivationReceived},
           {"vouch_needed", a.vouch_required},
           {"vouched", a.vouched},
           {"invites", std::move(invites)}};
    if (!a.inviter.empty()) j["inviter"] = {{"id", a.inviter}, {"pubkey", a.inviter_pubkey}};
    return j;
}

void Hub::handle_invite_status(const SessionPtr& s) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        identity = s->identity;
    }
    if (identity.empty()) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return;
    }
    send_json(s->conn, activation_json(identity));
}

// The inviter's word that a real conversation happened. The relay cannot see
// conversations; it only checks that the caller really is the identity whose
// code the other one claimed, and counts the invitee's own received traffic.
void Hub::handle_vouch(const SessionPtr& s, const json& j) {
    std::string identity;
    {
        std::lock_guard<std::mutex> lock(mu_);
        identity = s->identity;
    }
    if (identity.empty()) {
        send_error(s->conn, proto::kErrNotAuthorised, "send a hello with your id first");
        return;
    }
    const std::string target = util::to_lower(util::trim(j.value("id", std::string{})));
    if (!util::is_valid_fingerprint(target)) {
        send_error(s->conn, proto::kErrBadField, "id must be a fingerprint");
        return;
    }
    switch (db_.vouch(identity, target)) {
        case Db::VouchResult::ok: break;
        case Db::VouchResult::not_your_invitee:
            send_error(s->conn, proto::kErrNotAuthorised, "you did not invite that identity here");
            return;
        default:
            send_error(s->conn, proto::kErrInternal, "could not record the vouch");
            return;
    }
    if (const int n = db_.activate_if_ready(target, proto::kActivationReceived))
        log::info("identity ", log::short_id(target), " is active; ", n, " invite codes unlocked");
    const auto a = db_.activation(target, proto::kActivationReceived);
    send_json(s->conn, json{{"t", proto::kVouchOk}, {"id", target}, {"active", a.active}});
}

// -------------------------------------------------------------- routing ----

bool Hub::dialable(const std::string& address) const {
    auto a = util::parse_address(address, 8787);
    return a && peers_.acceptable(a->host);
}

bool Hub::route_to_relay(const std::string& address, std::string frame) {
    if (address.empty()) return false;
    if (address == self_address()) return false;
    if (!dialable(address)) return false;  // never a hop into someone's LAN

    ConnectionPtr link;
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = by_peer_address_.find(address);
        if (it != by_peer_address_.end()) {
            auto sit = sessions_.find(it->second);
            if (sit != sessions_.end()) link = sit->second->conn;
        }
    }
    if (link) {
        // Note: the outgoing hop uses whatever scheme that peer speaks. A frame
        // received on wss:// leaves over ws:// when the next relay is plaintext.
        link->send_text(std::move(frame));
        frames_out_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    if (dialer_) {
        dialer_->deliver_to_peer(address, std::move(frame));
        return true;
    }
    return false;
}

bool Hub::route_to_any(const std::vector<std::string>& candidates, std::string frame) {
    if (candidates.empty()) return false;
    for (const auto& a : candidates) {
        if (auto link = relay_link_for(a)) {
            link->send_text(std::move(frame));
            frames_out_.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
    }
    if (!dialer_) return false;
    // Dial healthy peers before ones already failing, keeping the sender's
    // order within each group.
    const std::int64_t now = util::now_unix();
    std::vector<std::string> ordered, later;
    for (const auto& a : candidates) {
        if (!dialable(a)) continue;
        auto p = peers_.find(a);
        (p && p->retry_after() > now ? later : ordered).push_back(a);
    }
    ordered.insert(ordered.end(), later.begin(), later.end());
    if (ordered.empty()) return false;
    dialer_->deliver_to_peer_alternates(ordered, std::move(frame));
    return true;
}

bool Hub::store_undeliverable_frame(const std::string& frame) {
    json j = json::parse(frame, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return false;
    // Only a `send` carries enough to re-address the payload. An onion layer
    // is sealed to the unreachable hop and cannot be stored for anyone.
    if (j.value("t", std::string{}) != proto::kSend) return false;

    const std::string msg_id = j.value("id", std::string{});
    if (!util::is_uuid_v4(msg_id)) return false;
    auto target = proto::parse_target(j.value("to", std::string{}));
    if (!target.valid) return false;
    if (!j.contains("body") || !j["body"].is_string()) return false;
    auto body = util::b64_decode(j["body"].get<std::string>());
    if (!body || body->empty() || body->size() > cfg_.max_payload_bytes) return false;

    std::string hint = j.value("hint", std::string{});
    if (hint.size() > 128) hint.clear();

    // The sender was already told "forwarded", so there is nobody to answer;
    // the payload is simply kept here where the recipient can still fetch it,
    // and the unreachable home (plus the rendezvous set) gets a pointer.
    return store_locally(msg_id, target.fingerprint, *body, hint, nullptr, target.relay);
}

void Hub::broadcast_to_relays(const std::string& frame) {
    for (const auto& c : relay_links()) {
        c->send_text(frame);
        frames_out_.fetch_add(1, std::memory_order_relaxed);
    }
}

std::vector<ConnectionPtr> Hub::relay_links() const {
    std::vector<ConnectionPtr> out;
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto& [cid, s] : sessions_)
        if (s->role == Role::relay) out.push_back(s->conn);
    return out;
}

ConnectionPtr Hub::relay_link_for(const std::string& address) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = by_peer_address_.find(address);
    if (it == by_peer_address_.end()) return nullptr;
    auto sit = sessions_.find(it->second);
    return sit == sessions_.end() ? nullptr : sit->second->conn;
}

std::set<std::string> Hub::connected_relay_addresses() const {
    std::set<std::string> out;
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto& [addr, cid] : by_peer_address_)
        if (sessions_.count(cid)) out.insert(addr);
    return out;
}

Hub::Stats Hub::stats() const {
    Stats st;
    {
        std::lock_guard<std::mutex> lock(mu_);
        st.connections = sessions_.size();
        for (const auto& [cid, s] : sessions_) {
            if (s->role == Role::relay) ++st.relay_links;
            else ++st.clients;
            if (s->conn->secure()) ++st.tls_connections;
        }
    }
    st.frames_in = frames_in_.load(std::memory_order_relaxed);
    st.frames_out = frames_out_.load(std::memory_order_relaxed);
    st.forwarded = forwarded_.load(std::memory_order_relaxed);
    st.onion_peeled = onion_peeled_.load(std::memory_order_relaxed);
    st.drops_accepted = drops_accepted_.load(std::memory_order_relaxed);
    st.drops_rejected = drops_rejected_.load(std::memory_order_relaxed);
    st.invites_burned = invites_burned_.load(std::memory_order_relaxed);
    return st;
}

}  // namespace r2r
