#include "peer_manager.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include <openssl/err.h>

#include <algorithm>
#include <functional>
#include <memory>
#include <type_traits>

#include <nlohmann/json.hpp>

#include "log.hpp"
#include "protocol.hpp"
#include "util.hpp"
#include "ws_channel.hpp"

using nlohmann::json;

namespace r2r {
namespace {

namespace beast = boost::beast;
namespace http = boost::beast::http;
namespace websocket = boost::beast::websocket;
using tcp = boost::asio::ip::tcp;

constexpr int kMaintainIntervalSeconds = 15;
constexpr int kDialTimeoutSeconds = 15;
constexpr std::size_t kMaxPendingFramesPerPeer = 64;
constexpr std::size_t kMaxPendingBytesPerPeer = 4u * 1024 * 1024;
constexpr std::int64_t kPendingGraceSeconds = 300;
constexpr std::size_t kGossipFanout = 3;
// Verification dials per maintain tick. An address that reached the table by
// gossip or by an inbound hello is dialled once to see whether a relay with
// the claimed key really answers there; until it does it is not trusted with
// anything. The budget bounds how fast a peer can make this relay open
// connections to addresses of its choosing: two every 15 seconds, public
// addresses only, and nothing observable comes back to whoever asked.
constexpr std::size_t kProbeDialsPerTick = 2;

using DialCallback = std::function<void(bool ok, const ConnectionPtr& link)>;

// Dials one relay and, on success, hands a live WsChannel to the Hub.
// Instantiated for PlainStream (ws://) and TlsStream (wss://).
template <class Stream>
class PeerDial final : public std::enable_shared_from_this<PeerDial<Stream>> {
public:
    static constexpr bool kTls = std::is_same_v<Stream, TlsStream>;

    template <class... StreamArgs>
    PeerDial(net::io_context& ioc, PeerInfo peer, Hub& hub, const Config& cfg, DialCallback done,
             StreamArgs&&... args)
        : resolver_(net::make_strand(ioc)),
          ws_(net::make_strand(ioc), std::forward<StreamArgs>(args)...),
          peer_(std::move(peer)),
          hub_(hub),
          cfg_(cfg),
          done_(std::move(done)) {}

    void run() {
        auto self = this->shared_from_this();
        resolver_.async_resolve(peer_.host, std::to_string(peer_.port),
                                [self](beast::error_code ec, tcp::resolver::results_type results) {
                                    self->on_resolve(ec, std::move(results));
                                });
    }

private:
    void fail(beast::error_code ec, const char* stage) {
        if (finished_) return;
        finished_ = true;
        log::debug("dial to ", peer_.address(), " failed at ", stage, ": ", ec.message());
        done_(false, nullptr);
    }

    void on_resolve(beast::error_code ec, tcp::resolver::results_type results) {
        if (ec) return fail(ec, "resolve");
        // A hostname passes the address policy only once resolved: a name that
        // points into loopback or a private range is refused here, so no peer
        // can steer a dial onto this relay's own network.
        std::vector<tcp::endpoint> endpoints;
        for (const auto& r : results) {
            const auto addr = r.endpoint().address().to_string();
            if (!cfg_.allow_private_peers && util::is_non_public_ip(addr)) {
                log::debug("dial to ", peer_.address(), ": ignoring non-public address ", addr);
                continue;
            }
            endpoints.push_back(r.endpoint());
        }
        if (endpoints.empty()) return fail(net::error::make_error_code(net::error::no_permission),
                                           "policy (no public address)");
        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(kDialTimeoutSeconds));
        auto self = this->shared_from_this();
        beast::get_lowest_layer(ws_).async_connect(
            endpoints, [self](beast::error_code ec2, const tcp::endpoint&) {
                self->on_connect(ec2);
            });
    }

    void on_connect(beast::error_code ec) {
        if (ec) return fail(ec, "connect");
        auto self = this->shared_from_this();
        if constexpr (kTls) {
            if (!SSL_set_tlsext_host_name(ws_.next_layer().native_handle(), peer_.host.c_str())) {
                beast::error_code sni{static_cast<int>(::ERR_get_error()),
                                      net::error::get_ssl_category()};
                return fail(sni, "sni");
            }
            ws_.next_layer().async_handshake(ssl::stream_base::client,
                                             [self](beast::error_code ec2) {
                                                 if (ec2) return self->fail(ec2, "tls");
                                                 self->on_ws_handshake_start();
                                             });
        } else {
            on_ws_handshake_start();
        }
    }

    void on_ws_handshake_start() {
        // Beast's own timeout policy takes over from here.
        beast::get_lowest_layer(ws_).expires_never();
        auto opt = websocket::stream_base::timeout::suggested(beast::role_type::client);
        opt.keep_alive_pings = true;
        opt.idle_timeout = std::chrono::seconds(180);
        ws_.set_option(opt);
        ws_.set_option(websocket::stream_base::decorator([](websocket::request_type& req) {
            req.set(http::field::user_agent, "r2r-relay/" R2R_VERSION);
            req.set(http::field::sec_websocket_protocol, proto::kSubprotocol);
        }));

        const std::string host_header = util::format_address(peer_.host, peer_.port);
        auto self = this->shared_from_this();
        ws_.async_handshake(host_header, "/r2r",
                            [self](beast::error_code ec) { self->on_handshake(ec); });
    }

    void on_handshake(beast::error_code ec) {
        if (ec) return fail(ec, "websocket");
        if (finished_) return;
        finished_ = true;

        auto channel = std::make_shared<WsChannel<Stream>>(
            std::move(ws_), hub_, ConnKind::outbound_peer, kTls, peer_.address(),
            cfg_.max_frame_bytes, cfg_.max_send_queue);
        channel->start();
        done_(true, channel);
    }

    tcp::resolver resolver_;
    websocket::stream<Stream> ws_;
    PeerInfo peer_;
    Hub& hub_;
    const Config& cfg_;
    DialCallback done_;
    bool finished_{false};
};

}  // namespace

// ---------------------------------------------------------- PeerManager ----

PeerManager::PeerManager(net::io_context& ioc, const Config& cfg, PeerRegistry& peers, Hub& hub,
                         Db& db, BlobStore& blobs)
    : ioc_(ioc),
      cfg_(cfg),
      peers_(peers),
      hub_(hub),
      db_(db),
      blobs_(blobs),
      client_ctx_(ssl::context::tls_client),
      maintain_timer_(ioc),
      health_timer_(ioc),
      gossip_timer_(ioc),
      persist_timer_(ioc),
      sweep_timer_(ioc) {
    client_ctx_.set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 |
                            ssl::context::no_sslv3 | ssl::context::no_tlsv1 |
                            ssl::context::no_tlsv1_1);
    if (cfg_.peer_tls_verify) {
        client_ctx_.set_default_verify_paths();
        client_ctx_.set_verify_mode(ssl::verify_peer);
    } else {
        // Relays normally present self-signed certificates. Transport privacy
        // still holds, and node identity is authenticated separately by the
        // ed25519 signature inside `hello`, pinned per address in peers.json.
        client_ctx_.set_verify_mode(ssl::verify_none);
    }
}

void PeerManager::arm(net::steady_timer& timer, int seconds, void (PeerManager::*handler)()) {
    if (stopped_.load()) return;
    timer.expires_after(std::chrono::seconds(seconds));
    timer.async_wait([this, handler](const boost::system::error_code& ec) {
        if (ec || stopped_.load()) return;
        (this->*handler)();
    });
}

void PeerManager::start() {
    log::info("peer manager starting: ", peers_.size(), " known peers, dial target ",
              cfg_.peer_dial_target);
    on_maintain();
    arm(health_timer_, cfg_.peer_ping_interval_s, &PeerManager::on_health);
    arm(gossip_timer_, cfg_.gossip_interval_s, &PeerManager::on_gossip);
    arm(persist_timer_, cfg_.peers_persist_interval_s, &PeerManager::on_persist);
    arm(sweep_timer_, 60, &PeerManager::on_sweep);
}

void PeerManager::stop() {
    stopped_.store(true);
    maintain_timer_.cancel();
    health_timer_.cancel();
    gossip_timer_.cancel();
    persist_timer_.cancel();
    sweep_timer_.cancel();
    peers_.save();
}

std::size_t PeerManager::outbound_links() const {
    std::size_t n = 0;
    for (const auto& c : hub_.relay_links())
        if (c->kind() == ConnKind::outbound_peer) ++n;
    return n;
}

// ---- dialling --------------------------------------------------------------

void PeerManager::dial(const PeerInfo& peer) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (!dialing_.insert(peer.address()).second) return;  // already in flight
    }
    peers_.mark_attempt(peer.address());
    log::debug("dialling peer ", peer.url());

    const std::string address = peer.address();
    auto done = [this, address](bool ok, const ConnectionPtr& link) {
        on_dial_result(address, ok, link);
    };

    if (peer.tls) {
        std::make_shared<PeerDial<TlsStream>>(ioc_, peer, hub_, cfg_, done, client_ctx_)->run();
    } else {
        std::make_shared<PeerDial<PlainStream>>(ioc_, peer, hub_, cfg_, done)->run();
    }
}

void PeerManager::on_dial_result(const std::string& address, bool ok, const ConnectionPtr& link) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        dialing_.erase(address);
    }
    if (!ok) {
        // Anything queued for this peer stays queued: the maintain timer will
        // try again until the grace period runs out. A relay that is briefly
        // down should not cost anyone their message. Frames that carry
        // alternatives (onion layers) move on to the next candidate now.
        peers_.mark_fail(address);
        std::vector<PendingFrame> moving;
        {
            std::lock_guard<std::mutex> lock(mu_);
            auto it = pending_.find(address);
            if (it != pending_.end()) {
                std::deque<PendingFrame> keep;
                for (auto& p : it->second) {
                    if (p.alternates.empty()) keep.push_back(std::move(p));
                    else moving.push_back(std::move(p));
                }
                if (keep.empty()) pending_.erase(it);
                else it->second.swap(keep);
            }
        }
        for (auto& p : moving) {
            const std::string next = p.alternates.front();
            std::vector<std::string> rest(p.alternates.begin() + 1, p.alternates.end());
            log::debug("dial to ", address, " failed; trying alternative ", next);
            if (auto link = hub_.relay_link_for(next)) link->send_text(std::move(p.frame));
            else enqueue(next, std::move(p.frame), std::move(rest));
        }
        return;
    }
    flush_pending(address, link);
}

void PeerManager::flush_pending(const std::string& address, const ConnectionPtr& link) {
    std::deque<PendingFrame> queued;
    {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = pending_.find(address);
        if (it == pending_.end()) return;
        queued.swap(it->second);
        pending_.erase(it);
    }
    // Our `hello` was queued first by Hub::on_open, so the remote authenticates
    // this link before it sees any of these frames.
    for (auto& p : queued) link->send_text(std::move(p.frame));
    if (!queued.empty())
        log::debug("flushed ", queued.size(), " queued frames to ", address);
}

std::size_t PeerManager::service_pending(const std::set<std::string>& connected) {
    const std::int64_t now = util::now_unix();

    std::vector<std::string> waiting;
    std::vector<std::string> undeliverable;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto it = pending_.begin(); it != pending_.end();) {
            auto& queue = it->second;
            while (!queue.empty() && now - queue.front().queued_at > kPendingGraceSeconds) {
                undeliverable.push_back(std::move(queue.front().frame));
                queue.pop_front();
            }
            if (queue.empty()) {
                it = pending_.erase(it);
                continue;
            }
            if (!dialing_.count(it->first)) waiting.push_back(it->first);
            ++it;
        }
    }
    const std::size_t expired = undeliverable.size();
    if (expired) {
        // A message must not vanish because its destination stayed down: park
        // it in the local dead drop instead, where the recipient can still
        // collect it. Only opaque frames (onion layers, control chatter) are
        // truly dropped.
        std::size_t stored = 0;
        for (auto& frame : undeliverable)
            if (hub_.store_undeliverable_frame(frame)) ++stored;
        if (stored)
            log::info("destination unreachable for ", kPendingGraceSeconds, "s; parked ", stored,
                      " of ", expired, " frames in the local dead drop");
        if (stored < expired)
            log::warn("gave up on ", expired - stored, " frames after ", kPendingGraceSeconds,
                      "s with no route to their destination");
    }

    for (const auto& address : waiting) {
        // A link may have appeared since these frames were queued -- including
        // one the peer dialled to us, which no dial of ours would ever flush.
        if (auto link = hub_.relay_link_for(address)) {
            flush_pending(address, link);
            continue;
        }
        if (connected.count(address)) continue;
        auto peer = peers_.find(address);
        if (!peer || peer->retry_after() > now) continue;
        dial(*peer);
    }
    return expired;
}

void PeerManager::deliver_to_peer(const std::string& address, std::string frame) {
    enqueue(address, std::move(frame), {});
}

void PeerManager::deliver_to_peer_alternates(const std::vector<std::string>& addresses,
                                             std::string frame) {
    if (addresses.empty()) return;
    enqueue(addresses.front(), std::move(frame),
            std::vector<std::string>(addresses.begin() + 1, addresses.end()));
}

void PeerManager::enqueue(const std::string& address, std::string frame,
                          std::vector<std::string> alternates) {
    auto known = peers_.find(address);
    PeerInfo peer;
    if (known) {
        peer = *known;
    } else {
        // An address we have never met: accept it, but only as a plain ws://
        // hop unless it explicitly says otherwise.
        bool tls = false;
        auto canon = PeerRegistry::canonicalise(address, tls);
        if (!canon) return;
        if (!peers_.add(*canon, tls, false)) {
            auto again = peers_.find(*canon);
            if (!again) return;
            peer = *again;
        } else {
            auto again = peers_.find(*canon);
            if (!again) return;
            peer = *again;
        }
    }

    {
        std::lock_guard<std::mutex> lock(mu_);
        auto& q = pending_[peer.address()];
        std::size_t bytes = 0;
        for (const auto& p : q) bytes += p.frame.size();
        if (q.size() >= kMaxPendingFramesPerPeer ||
            bytes + frame.size() > kMaxPendingBytesPerPeer) {
            log::warn("dropping a frame for ", peer.address(), ": its queue is full");
            return;
        }
        q.push_back({std::move(frame), util::now_unix(), std::move(alternates)});
    }
    dial(peer);
}

// ---- timers ----------------------------------------------------------------

void PeerManager::on_maintain() {
    const auto connected = hub_.connected_relay_addresses();
    const int deficit = cfg_.peer_dial_target - static_cast<int>(connected.size());
    if (deficit > 0) {
        // Links are made to peers already proven, and to the seeds.
        auto candidates = peers_.dial_candidates(static_cast<std::size_t>(deficit), connected);
        for (const auto& p : candidates) dial(p);
    }
    // Everything else gets a bounded trickle of verification dials, whether or
    // not it already holds an inbound link to us: a relay proves the address
    // it advertises by answering there, not by having called in.
    for (const auto& p : peers_.probe_candidates(kProbeDialsPerTick)) {
        log::debug("verifying ", p.address(), " by dialling it");
        dial(p);
    }
    // Peers with frames waiting are dialled regardless of the link budget:
    // something is already depending on them.
    service_pending(connected);
    arm(maintain_timer_, kMaintainIntervalSeconds, &PeerManager::on_maintain);
}

void PeerManager::on_health() {
    auto links = hub_.relay_links();
    if (!links.empty()) {
        const json ping{{"t", proto::kPing},
                        {"nonce", util::hex_encode(crypto::random_bytes(8))},
                        {"time", util::now_unix()}};
        const std::string frame = ping.dump();
        for (const auto& c : links) c->send_text(frame);
        log::debug("health ping sent to ", links.size(), " relay links");
    }
    arm(health_timer_, cfg_.peer_ping_interval_s, &PeerManager::on_health);
}

void PeerManager::on_gossip() {
    if (cfg_.gossip_enabled) {
        auto links = hub_.relay_links();
        if (!links.empty()) {
            const auto connected = hub_.connected_relay_addresses();
            auto chosen = peers_.random_addresses(kGossipFanout, connected);
            const std::string req = json{{"t", proto::kPeersReq}}.dump();
            std::size_t sent = 0;
            for (const auto& c : links) {
                const std::string& addr = c->dialled_address();
                const bool pick = chosen.empty() ||
                                  std::find(chosen.begin(), chosen.end(), addr) != chosen.end();
                if (!pick && sent >= kGossipFanout) continue;
                c->send_text(req);
                ++sent;
                if (sent >= kGossipFanout) break;
            }
            if (sent) log::debug("gossip round: asked ", sent, " peers for their peer lists");
        }
    }
    arm(gossip_timer_, cfg_.gossip_interval_s, &PeerManager::on_gossip);
}

void PeerManager::on_persist() {
    const std::size_t pruned = peers_.prune();
    if (peers_.save())
        log::info("peers.json rewritten: ", peers_.size(), " peers (", peers_.verified_count(),
                  " verified, ", pruned, " pruned)");
    arm(persist_timer_, cfg_.peers_persist_interval_s, &PeerManager::on_persist);
}

void PeerManager::on_sweep() {
    const std::int64_t now = util::now_unix();
    const int removed = db_.prune_expired(now);
    if (removed > 0) log::info("expired ", removed, " dead-drop payloads past their TTL");

    // Blob bytes outlive their references only until the next sweep: an id is
    // returned here once no owner refers to it any more.
    auto orphaned = db_.prune_blobs(now);
    std::size_t deleted = 0;
    for (const auto& id : orphaned)
        if (blobs_.remove(id)) ++deleted;
    if (deleted) log::info("deleted ", deleted, " expired voice/video blobs");

    const int stale_pointers = db_.prune_pointers(now);
    if (stale_pointers > 0) log::info("expired ", stale_pointers, " stale mail pointers");

    // Burned collection nonces outlive the freshness window, then go.
    db_.prune_authz(now - 8 * 86400);

    // Overdue rentals stop counting as quota and as committed inventory the
    // moment they lapse; the stored data then decays under normal TTL rules.
    const int lapsed = db_.rentals_lapse(now);
    if (lapsed > 0) log::info(lapsed, " storage rental(s) lapsed unpaid");

    arm(sweep_timer_, cfg_.db_prune_interval_s, &PeerManager::on_sweep);
}

}  // namespace r2r
