// R2R relay -- runtime configuration (defaults, environment, command line).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "log.hpp"

namespace r2r {

// Bootstrap relays written into peers.json the first time the node starts.
// All of them speak plain ws:// on 8787.
extern const char* const kSeedPeers[];
extern const std::size_t kSeedPeerCount;

struct Config {
    // --- listeners ---------------------------------------------------------
    std::string bind_addr = "0.0.0.0";
    std::uint16_t ws_port = 8787;    // plaintext: inter-relay gossip + local clients
    std::uint16_t wss_port = 8788;   // TLS: remote clients
    bool tls_enabled = true;
    std::string tls_cert = "/etc/r2r/tls/cert.pem";
    std::string tls_key = "/etc/r2r/tls/key.pem";

    // --- storage -----------------------------------------------------------
    std::string data_dir = "/var/lib/r2r";
    std::string peers_file;    // default: <data_dir>/peers.json
    std::string db_file;       // default: <data_dir>/r2r.db
    std::string node_key_file; // default: <data_dir>/node.key
    std::string assets_dir;    // optional: files published under GET /assets/
    std::size_t max_asset_bytes = 64u * 1024 * 1024;
    std::string blob_dir;      // default: <data_dir>/blobs

    // --- doorway (the embedded web site) ------------------------------------
    std::string doorway_dir;   // default: <data_dir>/doorway; served when present
    std::string base_path;     // "" for root, "/R2R" when mounted under a prefix
    std::string primary_color = "#0EADB5";
    std::string secondary_color = "#F26430";

    // --- voice, video and history -----------------------------------------
    // Blobs hold recorded voice and video messages, so the ceiling is far
    // above the WebSocket payload limit; they travel over HTTP, not frames.
    std::size_t max_blob_bytes = 24u * 1024 * 1024;
    std::size_t max_journal_entry_bytes = 640 * 1024;
    int journal_read_limit = 200;
    std::size_t journal_read_bytes = 2u * 1024 * 1024;

    // --- WebRTC ------------------------------------------------------------
    // Handed to clients so they can establish a direct peer connection. Media
    // never passes through the relay; without a TURN server, calls between two
    // symmetric NATs will fail to connect.
    std::string stun_url = "stun:stun.l.google.com:19302";
    std::string turn_url;
    std::string turn_user;   // static credentials; only if no secret is set
    std::string turn_pass;
    // Preferred: coturn's `use-auth-secret` mode. The relay derives a username
    // that expires and a password that is an HMAC of it, so nothing long-lived
    // is ever handed to a client and the secret stays on the server.
    std::string turn_secret;
    std::string turn_secret_file;
    int ice_ttl_seconds = 600;

    // --- identity on the network ------------------------------------------
    std::string advertise;     // "host:port" this relay publishes to peers
    std::vector<std::string> extra_seeds;  // --seed / R2R_SEEDS, added to the built-in list

    // --- behaviour ---------------------------------------------------------
    int threads = 0;                       // 0 -> hardware_concurrency
    int drop_ttl_days = 7;                 // dead-drop retention
    int peer_ping_interval_s = 30;
    int gossip_interval_s = 60;
    int peers_persist_interval_s = 300;    // rewrite peers.json every 5 minutes
    int db_prune_interval_s = 900;
    int peer_dial_target = 8;              // outbound links we try to maintain
    int max_hops = 8;                      // forwarding TTL for relayed frames
    std::size_t max_peers = 512;
    std::size_t max_payload_bytes = 256 * 1024;
    std::size_t max_frame_bytes = 1024 * 1024;
    std::size_t max_send_queue = 256;
    double rate_frames_per_sec = 40.0;
    double rate_burst = 120.0;
    bool require_invite = true;            // identity registration needs a code
    bool gossip_enabled = true;
    bool peer_tls_verify = false;          // relays normally use self-signed certs
    bool allow_plaintext_bridge = true;    // wss:// in -> ws:// out when the peer is plaintext
    // Peer addresses on loopback, private or link-local ranges are refused,
    // whether they arrive by gossip, in a hello, in peers.json or as a client's
    // "fp@host:port" destination. Only a test bench wants this off.
    bool allow_private_peers = false;

    // --- process -----------------------------------------------------------
    std::string run_as_user;               // drop privileges after binding
    log::Level log_level = log::Level::info;

    // --- storage allowances ------------------------------------------------
    // Default matches the old relay's DEFAULT_QUOTA_MB=1. Individual users are
    // raised above it with --set-quota; only the exceptions are stored.
    std::int64_t default_quota_mb = 1;
    std::int64_t max_drops_per_user = 4096;

    // --- storage pools ------------------------------------------------------
    // How the relay's disk is budgeted. `common` caps the total held for
    // free-tier identities (everyone without a custom quota) so the common
    // good cannot swallow the disk; identities the operator granted a custom
    // quota are governed by that quota alone. `market` and `personal` are
    // declared budgets for the replication economy and the operator's own
    // use -- accounted and published, not yet enforced. 0 = unlimited.
    std::int64_t pool_common_mb = 0;
    std::int64_t pool_market_mb = 0;
    std::int64_t pool_personal_mb = 0;

    // --- storage market -----------------------------------------------------
    // The market is on when a market pool is budgeted AND a payout address is
    // set. Price is micro-USDC per GB-epoch; the default sits above the
    // priciest surveyed VPS so an honest operator profits anywhere.
    // See docs/settlement-design.md.
    std::int64_t market_price_micro = 500000;  // $0.50 per GB-epoch
    std::string payout_address;                // 0x…, empty = market disabled
    std::string vault_address;                 // informational, wallets cross-check
    std::int64_t chain_id = 8453;              // Base
    int rent_epoch_days = 31;
    int rent_grace_days = 35;  // first epoch, before the first voucher

    bool market_enabled() const { return pool_market_mb > 0 && !payout_address.empty(); }

    // Behind a TLS-terminating proxy (nginx on 443 -> plain ws on ws_port),
    // the dialable address for wallets is not derivable from our own
    // listeners. When set, cards and contact pages advertise exactly this.
    std::string public_ws_url;  // e.g. wss://r2r.homes/ws

    // --- one-shot admin actions -------------------------------------------
    int mint_invites = 0;                  // mint N codes, print them, exit
    std::string quota_target;              // fingerprint for --set/get/clear-quota
    std::int64_t set_quota_mb = -1;        // >= 0 -> apply and exit
    bool clear_quota = false;
    bool show_quotas = false;
    std::string owner_add;     // fingerprint to trust as a relay owner
    std::string owner_remove;
    bool show_owners = false;

    void finalize();                       // fills in derived paths
    std::vector<std::string> validate() const;  // returns human-readable problems
};

// Returns false if the process should exit (--help / --version / bad args);
// `exit_code` carries the status to exit with.
bool parse_command_line(int argc, char** argv, Config& cfg, int& exit_code);
void apply_environment(Config& cfg);
std::string usage_text(const char* argv0);

}  // namespace r2r
