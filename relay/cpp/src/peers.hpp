// R2R relay -- the peer table and its on-disk form, peers.json.
#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace r2r {

struct PeerInfo {
    std::string host;
    std::uint16_t port{0};
    bool tls{false};             // true -> reach it with wss://
    bool seed{false};            // from the bootstrap list; never pruned away
    // True only once THIS relay dialled the address and the node answering
    // there proved its key. An inbound hello or a gossip entry never sets it:
    // anyone can claim an address, only the node reachable at it can prove it.
    bool verified{false};
    std::string node_id;         // learned from its `hello`
    std::string ed25519;         // base64; a hint until verified, a pin after
    std::string x25519;          // base64, used to seal onion layers for it
    std::int64_t first_seen{0};
    std::int64_t last_ok{0};
    std::int64_t last_attempt{0};
    int failures{0};

    std::string address() const;
    std::string url() const;                       // ws://host:port or wss://...
    std::int64_t retry_after() const;              // earliest sensible next dial
};

// Peer addresses are public infrastructure, so this table is safe to publish.
// It contains no information about users.
class PeerRegistry {
public:
    struct GossipEntry {
        std::string address;
        bool tls{false};
        std::string node_id;
        std::string ed25519;
        std::string x25519;
    };

    PeerRegistry();

    void configure(std::string file, std::size_t max_peers, std::int64_t prune_after_s,
                   bool allow_private = false);
    // Bootstrap relays: the built-in list plus --seed. Only these are ever
    // treated as seeds; a "seed" flag in an older peers.json is not trusted.
    void set_seeds(const std::vector<std::string>& extra);
    void set_self(std::string advertise, std::string node_id, std::string ed25519,
                  std::string x25519);

    // Reads peers.json; if it is missing or unusable, seeds the table from the
    // built-in bootstrap list and writes a fresh file.
    bool load_or_bootstrap();
    bool save();

    bool add(std::string_view address_or_url, bool tls, bool seed = false);
    // Adds at most `max_new` addresses from one gossip frame; the rest of the
    // frame may still refresh key hints on entries already known.
    std::size_t merge(const std::vector<GossipEntry>& entries, std::size_t max_new);
    std::vector<GossipEntry> export_gossip(std::size_t max) const;
    // True when the address is one this relay may hold and dial at all.
    bool acceptable(std::string_view host) const;

    void mark_attempt(const std::string& address);
    // The address answered a dial of ours with a valid handshake: verify it
    // and pin its keys.
    void mark_ok(const std::string& address, const std::string& node_id,
                 const std::string& ed25519, const std::string& x25519);
    // Keys claimed for an address we have not reached ourselves (an inbound
    // hello, a gossip entry). Recorded as hints on unverified entries only.
    void learn_keys(const std::string& address, const std::string& node_id,
                    const std::string& ed25519, const std::string& x25519);
    // A verified peer showed signs of life over an existing link.
    void mark_alive(const std::string& address);
    void mark_fail(const std::string& address);

    std::vector<PeerInfo> all() const;
    std::vector<PeerInfo> verified_peers() const;
    // Peers worth linking to right now, best first, excluding `connected`:
    // only ones already verified, plus the configured seeds.
    std::vector<PeerInfo> dial_candidates(std::size_t n,
                                          const std::set<std::string>& connected) const;
    // Unverified, non-seed addresses due for a verification dial, the ones
    // waiting longest first. Includes addresses with an inbound link: a relay
    // that dialled us still has to prove it is reachable where it claims.
    std::vector<PeerInfo> probe_candidates(std::size_t n) const;
    std::vector<std::string> random_addresses(std::size_t n,
                                              const std::set<std::string>& pool) const;
    std::optional<PeerInfo> find(const std::string& address) const;
    std::optional<PeerInfo> find_by_node(const std::string& node_id) const;

    std::size_t prune();
    std::size_t size() const;
    std::size_t verified_count() const;

    bool is_self(std::string_view address) const;
    bool is_self_node(std::string_view node_id) const;
    // Called when a dial turns out to loop back to this very relay: the
    // address is dropped and never re-added, however often it is gossiped.
    void mark_self_alias(const std::string& address);

    nlohmann::json to_file_json() const;    // full state, written to peers.json
    nlohmann::json to_public_json() const;  // served on GET /peers.json

    // "ws://host:port" / "wss://host:port" / "host:port" -> canonical address.
    static std::optional<std::string> canonicalise(std::string_view input, bool& tls_out);

private:
    void evict_if_needed();                 // caller holds mu_
    bool add_locked(std::string_view address_or_url, bool tls, bool seed);
    void learn_locked(PeerInfo& p, const std::string& node_id, const std::string& ed25519,
                      const std::string& x25519);

    mutable std::mutex mu_;
    std::map<std::string, PeerInfo> peers_;
    std::string file_;
    std::string self_address_;
    std::string self_node_id_;
    std::string self_ed25519_;
    std::string self_x25519_;
    std::set<std::string> self_aliases_;
    std::vector<std::string> seeds_;  // canonical addresses
    std::size_t max_peers_{512};
    std::int64_t prune_after_s_{3600};
    bool allow_private_{false};
    mutable std::mt19937_64 rng_;
};

}  // namespace r2r
