// R2R relay -- application logic shared by every listener and every link.
//
// The Hub is deliberately transport-blind: it sees `Connection`, not sockets.
// That is what makes ws:// (8787) and wss:// (8788) behave identically, and
// what lets a frame that arrived over TLS leave over plaintext to a peer that
// only speaks ws:// -- the encrypted-bridge behaviour the network relies on.
#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include "config.hpp"
#include "connection.hpp"
#include "crypto.hpp"
#include "db.hpp"
#include "onion.hpp"
#include "peers.hpp"
#include "util.hpp"

namespace r2r {

class BlobStore;

// Implemented by PeerManager: opens a link on demand and queues the frame.
class PeerDialer {
public:
    virtual ~PeerDialer() = default;
    virtual void deliver_to_peer(const std::string& address, std::string frame) = 0;
    // Like deliver_to_peer, but when a dial fails the frame moves on to the
    // next address instead of waiting: onion alternatives.
    virtual void deliver_to_peer_alternates(const std::vector<std::string>& addresses,
                                            std::string frame) = 0;
};

// Remembers recently seen message ids so a frame cannot circulate forever.
class SeenCache {
public:
    explicit SeenCache(std::int64_t ttl_seconds = 900, std::size_t cap = 200000);
    bool insert(const std::string& key);  // false if the key was already known
    std::size_t size() const;

private:
    void expire(std::int64_t now);  // caller holds mu_

    mutable std::mutex mu_;
    std::unordered_set<std::string> set_;
    std::deque<std::pair<std::int64_t, std::string>> order_;
    std::int64_t ttl_;
    std::size_t cap_;
};

class Hub final : public ChannelSink {
public:
    Hub(const Config& cfg, Db& db, PeerRegistry& peers, const crypto::NodeIdentity& node);

    void set_dialer(PeerDialer* dialer) { dialer_ = dialer; }

    // --- ChannelSink -------------------------------------------------------
    void on_open(const ConnectionPtr& c) override;
    void on_text(const ConnectionPtr& c, std::string&& msg) override;
    void on_close(const ConnectionPtr& c) override;

    // --- routing -----------------------------------------------------------
    // True if the frame was handed to an existing link or queued for dialling.
    bool route_to_relay(const std::string& address, std::string frame);
    // First candidate with a live link wins; otherwise dial them in order,
    // healthy peers first, falling through on failure.
    bool route_to_any(const std::vector<std::string>& candidates, std::string frame);
    // Last resort for a forwarded frame whose destination stayed unreachable
    // past the retry grace period: a `send` is stored in the local dead drop
    // (the recipient can still collect it here), anything else is dropped.
    // Returns true if the payload was preserved.
    bool store_undeliverable_frame(const std::string& frame);
    void broadcast_to_relays(const std::string& frame);
    std::set<std::string> connected_relay_addresses() const;
    std::vector<ConnectionPtr> relay_links() const;
    // The live link to a relay, whichever side dialled it. Null if there is none.
    ConnectionPtr relay_link_for(const std::string& address) const;

    // --- shared with the HTTP layer ---------------------------------------
    struct ClaimOutcome {
        bool ok{false};
        std::string error;                 // proto::kErr* on failure
        std::vector<std::string> invites;  // three fresh codes on success
        bool locked{false};                // they unlock once this member is active
        std::string inviter;               // fingerprint of the identity that invited, if any
        std::string inviter_pubkey;        // its ed25519 key (b64), so the wallet can say hello
    };
    // `req` carries code, id, pubkey, ts, nonce, sig and an optional
    // home_relay. The identity proof is mandatory: registering a home relay
    // for a fingerprint you cannot sign for would redirect that user's mail.
    ClaimOutcome claim_invite(const nlohmann::json& req);

    // Checks a client's proof of key possession. Used by `hello` and by every
    // path that binds or registers an identity.
    struct ClientProof {
        bool ok{false};
        std::string fingerprint;
        std::string pubkey_b64;
        std::string error;  // proto::kErr* when !ok
    };
    ClientProof verify_client_proof(const nlohmann::json& j) const;

    struct Stats {
        std::size_t connections{0};
        std::size_t clients{0};
        std::size_t relay_links{0};
        std::size_t tls_connections{0};
        std::int64_t frames_in{0};
        std::int64_t frames_out{0};
        std::int64_t forwarded{0};
        std::int64_t onion_peeled{0};
        std::int64_t drops_accepted{0};
        std::int64_t drops_rejected{0};
        std::int64_t invites_burned{0};
    };
    Stats stats() const;

    // The advertise address is admin-changeable at runtime, so reads take a
    // snapshot under its own lock.
    std::string self_address() const {
        std::lock_guard<std::mutex> lock(addr_mu_);
        return self_address_;
    }
    // Applies a new advertise address: updates the peer registry's notion of
    // self, persists the override, and tells whoever registered an interest
    // (the doorway re-renders its {{HOST}}).
    bool set_advertise(const std::string& canonical);
    void set_advertise_hook(std::function<void(const std::string&)> hook) {
        advertise_hook_ = std::move(hook);
    }
    void set_blobstore(BlobStore* blobs) { blobs_ = blobs; }
    nlohmann::json identity_frame(const char* type) const;  // signed hello/welcome

private:
    enum class Role { unknown, client, relay };

    static constexpr std::size_t kGossipNewPerSession = 64;

    struct Session {
        ConnectionPtr conn;
        Role role{Role::unknown};
        std::string identity;      // client fingerprint, if declared
        std::string node_id;       // relay node id, once verified
        std::string peer_address;  // relay advertise address, once verified
        bool subscribed{false};
        bool push{false};          // subscribe{push:true}: deliver drops live
        bool greeted{false};
        // New addresses this session may still add to the peer table by
        // gossip. Bounds how much one relay can pad the table per connection.
        std::size_t gossip_new_left{kGossipNewPerSession};
        std::string presence_state{"online"};   // "online" or "away"
        std::set<std::string> watching;         // identities this session watches
        std::int64_t connected_at{0};
        std::int64_t last_fetch{0};
        util::TokenBucket bucket;      // inbound frames
        util::TokenBucket err_bucket;  // outbound `err` frames -- see send_error
        int rate_strikes{0};
        // All fields above are guarded by Hub::mu_.
    };
    using SessionPtr = std::shared_ptr<Session>;

    SessionPtr session_for(const std::string& conn_id) const;
    void send_json(const ConnectionPtr& c, const nlohmann::json& j);
    void send_error(const ConnectionPtr& c, std::string_view code, std::string_view msg,
                    std::string_view ref = {});

    void handle_frame(const SessionPtr& s, const nlohmann::json& j);
    void handle_identity(const SessionPtr& s, const nlohmann::json& j, bool is_welcome);
    void handle_send(const SessionPtr& s, const nlohmann::json& j);
    void handle_onion(const SessionPtr& s, const nlohmann::json& j);
    void handle_fetch(const SessionPtr& s, const nlohmann::json& j);
    void handle_ack(const SessionPtr& s, const nlohmann::json& j);
    void handle_ping(const SessionPtr& s, const nlohmann::json& j);
    void handle_pong(const SessionPtr& s, const nlohmann::json& j);
    void handle_peers_req(const SessionPtr& s);
    void handle_peers(const SessionPtr& s, const nlohmann::json& j);
    void handle_invite_claim(const SessionPtr& s, const nlohmann::json& j);
    void handle_subscribe(const SessionPtr& s, const nlohmann::json& j);
    void handle_quota(const SessionPtr& s);
    void handle_vouch(const SessionPtr& s, const nlohmann::json& j);
    void handle_invite_status(const SessionPtr& s);
    nlohmann::json activation_json(const std::string& fingerprint);

    // Mail pointers: emitted after storing for an identity this relay does
    // not home, routed to its home relay when known, else to its rendezvous
    // set; `locate` answers a session's "where else is my mail?".
    void handle_pointer(const SessionPtr& s, const nlohmann::json& j);
    void handle_locate(const SessionPtr& s);

    // Safe deposit: a session hands its relay single-use, holder-bound
    // collection authorizations; the relay presents them to the holding
    // relays and gathers the mail home.
    void handle_deposit(const SessionPtr& s, const nlohmann::json& j);
    void handle_collect(const SessionPtr& s, const nlohmann::json& j);
    void handle_collect_item(const SessionPtr& s, const nlohmann::json& j);
    void handle_collect_done(const SessionPtr& s, const nlohmann::json& j);
    void emit_pointer_if_remote(const std::string& recipient, const std::string& home_hint = {});
    // The k relays deterministically responsible for a fingerprint, ranked by
    // sha256("r2r-rdv-v1" + fp + node_id) over the verified peer set plus
    // this relay itself. Both ends of a lookup compute the same list.
    std::vector<std::string> rendezvous_addresses(const std::string& fp, std::size_t k,
                                                  bool* self_in_set) const;

    // Storage market: paid reservations and settlement vouchers.
    void handle_rent(const SessionPtr& s, const nlohmann::json& j);
    void handle_voucher(const SessionPtr& s, const nlohmann::json& j);

    // Relay administration from the owner's wallet.
    void handle_admin_accounts(const SessionPtr& s, const nlohmann::json& j);
    void handle_admin_set_quota(const SessionPtr& s, const nlohmann::json& j);
    void handle_admin_invites(const SessionPtr& s, const nlohmann::json& j);
    void handle_admin_revoke_invite(const SessionPtr& s, const nlohmann::json& j);
    void handle_admin_list_invites(const SessionPtr& s, const nlohmann::json& j);
    void handle_admin_set_ttl(const SessionPtr& s, const nlohmann::json& j);
    void handle_admin_search_accounts(const SessionPtr& s, const nlohmann::json& j);
    void handle_admin_delete_account(const SessionPtr& s, const nlohmann::json& j);
    void handle_admin_set_advertise(const SessionPtr& s, const nlohmann::json& j);
    void handle_admin_list_rentals(const SessionPtr& s);
    void handle_admin_list_vouchers(const SessionPtr& s);
    // Returns the caller's fingerprint if it is a relay owner, else empty and
    // an error has already been sent.
    std::string require_owner(const SessionPtr& s);

    // Calls: opaque signalling between two clients, plus the ICE servers they
    // need to find each other. Media never touches the relay.
    void handle_sig(const SessionPtr& s, const nlohmann::json& j);
    void handle_ice(const SessionPtr& s);
    void handle_watch(const SessionPtr& s, const nlohmann::json& j);
    void handle_presence(const SessionPtr& s, const nlohmann::json& j);

    // The client's own encrypted history, so a new browser can rebuild it.
    void handle_journal_append(const SessionPtr& s, const nlohmann::json& j);
    void handle_journal_read(const SessionPtr& s, const nlohmann::json& j);

    std::vector<ConnectionPtr> connections_for(const std::string& fingerprint) const;
    nlohmann::json presence_frame(const std::string& fingerprint) const;  // caller must not hold mu_
    void push_presence(const std::string& fingerprint);

    // Stores a payload in the local dead drop and nudges the recipient if it
    // happens to be online.
    // `home_hint`: the recipient's relay when the sender named it (fp@home)
    // but it could not be reached; pointers then go there too.
    bool store_locally(const std::string& msg_id, const std::string& recipient,
                       const util::Bytes& body, const std::string& from_hint,
                       const ConnectionPtr& reply_to, const std::string& home_hint = {});
    void deliver_terminal(const onion::Terminal& d);
    void notify_recipient(const std::string& fingerprint);

    // Verifies a signed hello/welcome and returns the peer's advertise address.
    struct PeerClaim {
        bool ok{false};
        std::string node_id;
        std::string advertise;
        std::string ed25519;
        std::string x25519;
        bool tls{false};
    };
    PeerClaim verify_peer_claim(const nlohmann::json& j) const;

    void index_relay(const SessionPtr& s, const PeerClaim& claim);
    void drop_impostors(const PeerClaim& claim);
    // A relay session whose address this node has itself dialled and verified.
    bool session_is_verified_relay(const SessionPtr& s) const;
    // False for addresses the peer policy refuses (loopback, private ranges).
    bool dialable(const std::string& address) const;
    void unindex(const SessionPtr& s);

    const Config& cfg_;
    Db& db_;
    PeerRegistry& peers_;
    const crypto::NodeIdentity& node_;
    PeerDialer* dialer_{nullptr};
    BlobStore* blobs_{nullptr};
    std::function<void(const std::string&)> advertise_hook_;
    mutable std::mutex addr_mu_;
    std::string self_address_;  // guarded by addr_mu_

    mutable std::mutex mu_;
    std::unordered_map<std::string, SessionPtr> sessions_;                 // conn id -> session
    std::unordered_multimap<std::string, std::string> by_identity_;        // fingerprint -> conn id
    std::unordered_map<std::string, std::string> by_peer_address_;         // host:port -> conn id
    std::unordered_map<std::string, std::string> by_node_id_;              // node id -> conn id
    std::unordered_map<std::string, std::set<std::string>> watchers_;      // watched -> conn ids
    std::unordered_map<std::string, std::int64_t> last_seen_;              // identity -> unix time
    std::unordered_map<std::string, std::int64_t> collecting_;  // "fp|holder" -> expires

    mutable SeenCache seen_;  // message ids, pointer keys and spent proof nonces

    std::atomic<std::int64_t> frames_in_{0};
    std::atomic<std::int64_t> frames_out_{0};
    std::atomic<std::int64_t> forwarded_{0};
    std::atomic<std::int64_t> onion_peeled_{0};
    std::atomic<std::int64_t> drops_accepted_{0};
    std::atomic<std::int64_t> drops_rejected_{0};
    std::atomic<std::int64_t> invites_burned_{0};
};

}  // namespace r2r
