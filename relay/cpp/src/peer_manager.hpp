// R2R relay -- outbound peer links, health pings, gossip and persistence.
//
// Timers owned here:
//   maintain  keep up to --peer-dial-target outbound links alive
//   health    ping every link; unanswered links fall out and get re-dialled
//   gossip    swap peer lists with a random handful of connected relays
//   persist   prune dead peers and rewrite peers.json (every 5 minutes)
//   sweep     delete dead-drop payloads past their TTL
#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>

#include <atomic>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>

#include "blobstore.hpp"
#include "config.hpp"
#include "connection.hpp"
#include "crypto.hpp"
#include "db.hpp"
#include "hub.hpp"
#include "peers.hpp"

namespace r2r {

namespace net = boost::asio;
namespace ssl = boost::asio::ssl;

class PeerManager final : public PeerDialer {
public:
    PeerManager(net::io_context& ioc, const Config& cfg, PeerRegistry& peers, Hub& hub, Db& db,
                BlobStore& blobs);

    void start();
    void stop();

    // PeerDialer: queue the frame and open a link if there is not one already.
    void deliver_to_peer(const std::string& address, std::string frame) override;
    void deliver_to_peer_alternates(const std::vector<std::string>& addresses,
                                    std::string frame) override;

    std::size_t outbound_links() const;

private:
    void arm(net::steady_timer& timer, int seconds, void (PeerManager::*handler)());

    void on_maintain();
    void on_health();
    void on_gossip();
    void on_persist();
    void on_sweep();

    void dial(const PeerInfo& peer);
    void on_dial_result(const std::string& address, bool ok, const ConnectionPtr& link);
    void flush_pending(const std::string& address, const ConnectionPtr& link);
    // Delivers or re-dials for anything still queued; drops frames past their
    // grace period. Returns how many were given up on.
    std::size_t service_pending(const std::set<std::string>& connected);

    net::io_context& ioc_;
    const Config& cfg_;
    PeerRegistry& peers_;
    Hub& hub_;
    Db& db_;
    BlobStore& blobs_;
    ssl::context client_ctx_;

    net::steady_timer maintain_timer_;
    net::steady_timer health_timer_;
    net::steady_timer gossip_timer_;
    net::steady_timer persist_timer_;
    net::steady_timer sweep_timer_;

    // A frame waiting for a link to the peer it is addressed to.
    struct PendingFrame {
        std::string frame;
        std::int64_t queued_at{0};
        std::vector<std::string> alternates;  // where to go if this peer's dial fails
    };
    void enqueue(const std::string& address, std::string frame, std::vector<std::string> alternates);

    mutable std::mutex mu_;
    std::set<std::string> dialing_;
    std::map<std::string, std::deque<PendingFrame>> pending_;
    std::atomic<bool> stopped_{false};
};

}  // namespace r2r
