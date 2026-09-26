#include "config.hpp"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string_view>

#include "util.hpp"

namespace r2r {

// The network the v2 relays form. Only nodes running this relay belong here;
// operators add more with --seed (or R2R_SEEDS) without a rebuild.
const char* const kSeedPeers[] = {
    "92.113.147.233:8787",  // r2r.homes
    // The second tier, replaced on 2026-09-25; each one lists all the others,
    // so a fresh install bootstraps even when r2r.homes is down.
    "143.110.227.46:8787",
    "164.90.207.73:8787",
    "164.92.156.207:8787",
    "165.22.204.117:8787",
    "165.232.132.110:8787",
};
const std::size_t kSeedPeerCount = sizeof(kSeedPeers) / sizeof(kSeedPeers[0]);

namespace {

bool parse_u16(std::string_view s, std::uint16_t& out) {
    char* end = nullptr;
    const std::string tmp(s);
    const long v = std::strtol(tmp.c_str(), &end, 10);
    if (!end || *end != '\0' || v <= 0 || v > 65535) return false;
    out = static_cast<std::uint16_t>(v);
    return true;
}

bool parse_int(std::string_view s, int& out, int lo, int hi) {
    char* end = nullptr;
    const std::string tmp(s);
    const long v = std::strtol(tmp.c_str(), &end, 10);
    if (!end || *end != '\0' || v < lo || v > hi) return false;
    out = static_cast<int>(v);
    return true;
}

bool parse_size(std::string_view s, std::size_t& out, std::size_t lo, std::size_t hi) {
    char* end = nullptr;
    const std::string tmp(s);
    const unsigned long long v = std::strtoull(tmp.c_str(), &end, 10);
    if (!end || *end != '\0' || v < lo || v > hi) return false;
    out = static_cast<std::size_t>(v);
    return true;
}

const char* env_or_null(const char* name) {
    const char* v = std::getenv(name);
    return (v && *v) ? v : nullptr;
}

}  // namespace

void Config::finalize() {
    if (data_dir.empty()) data_dir = ".";
    if (peers_file.empty()) peers_file = util::path_join(data_dir, "peers.json");
    if (db_file.empty()) db_file = util::path_join(data_dir, "r2r.db");
    if (node_key_file.empty()) node_key_file = util::path_join(data_dir, "node.key");
    if (blob_dir.empty()) blob_dir = util::path_join(data_dir, "blobs");
    if (doorway_dir.empty()) doorway_dir = util::path_join(data_dir, "doorway");

    // "/R2R/" and "R2R" both mean "/R2R"; "" and "/" both mean the root.
    if (!base_path.empty()) {
        if (base_path.back() == '/') base_path.pop_back();
        if (!base_path.empty() && base_path.front() != '/') base_path.insert(0, "/");
    }

    // Reading the secret from a file keeps it out of the process list and out
    // of the unit file, which is where an operator is most likely to leak it.
    if (turn_secret.empty() && !turn_secret_file.empty()) {
        if (auto s = util::read_file(turn_secret_file)) turn_secret = util::trim(*s);
    }
}

namespace {

bool is_hex_color(const std::string& s) {
    if (s.size() != 7 || s[0] != '#') return false;
    for (std::size_t i = 1; i < s.size(); ++i) {
        const char c = s[i];
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok) return false;
    }
    return true;
}

}  // namespace

std::vector<std::string> Config::validate() const {
    std::vector<std::string> problems;
    if (tls_enabled && ws_port == wss_port)
        problems.push_back("--ws-port and --wss-port must differ");
    if (!base_path.empty()) {
        if (base_path == "/" || base_path.find("//") != std::string::npos ||
            base_path.find(' ') != std::string::npos)
            problems.push_back("--base-path must look like /R2R");
        // The invite short-URL namespace /R2R-XXXX… is distinguished from a
        // base path by the character after "R2R": a dash is always a code.
    }
    if (!is_hex_color(primary_color) || !is_hex_color(secondary_color))
        problems.push_back("brand colors must be #RRGGBB");
    if (drop_ttl_days < 1 || drop_ttl_days > 365)
        problems.push_back("--ttl-days must be between 1 and 365");
    if (max_payload_bytes + 4096 > max_frame_bytes)
        problems.push_back("--max-payload must leave room inside --max-frame");
    if (!advertise.empty() && !util::parse_address(advertise, ws_port))
        problems.push_back("--advertise must look like host or host:port");
    for (const auto& s : extra_seeds)
        if (!util::parse_address(s, 8787)) problems.push_back("--seed must look like host:port: " + s);
    auto is_evm_address = [](const std::string& a) {
        if (a.size() != 42 || a[0] != '0' || (a[1] != 'x' && a[1] != 'X')) return false;
        for (std::size_t i = 2; i < a.size(); ++i)
            if (!std::isxdigit(static_cast<unsigned char>(a[i]))) return false;
        return true;
    };
    if (!payout_address.empty() && !is_evm_address(payout_address))
        problems.push_back("--payout-address must be a 0x… EVM address");
    if (!vault_address.empty() && !is_evm_address(vault_address))
        problems.push_back("--vault-address must be a 0x… EVM address");
    if (!public_ws_url.empty() && public_ws_url.rfind("ws://", 0) != 0 &&
        public_ws_url.rfind("wss://", 0) != 0)
        problems.push_back("--public-ws-url must start with ws:// or wss://");
    return problems;
}

void apply_environment(Config& cfg) {
    if (const char* v = env_or_null("R2R_DATA_DIR")) cfg.data_dir = v;
    if (const char* v = env_or_null("R2R_PEERS_FILE")) cfg.peers_file = v;
    if (const char* v = env_or_null("R2R_DB_FILE")) cfg.db_file = v;
    if (const char* v = env_or_null("R2R_ASSETS_DIR")) cfg.assets_dir = v;
    if (const char* v = env_or_null("R2R_DOORWAY_DIR")) cfg.doorway_dir = v;
    if (const char* v = env_or_null("R2R_BASE_PATH")) cfg.base_path = v;
    if (const char* v = env_or_null("R2R_PRIMARY_COLOR")) cfg.primary_color = v;
    if (const char* v = env_or_null("R2R_SECONDARY_COLOR")) cfg.secondary_color = v;
    auto pool_env = [](const char* name, std::int64_t& out) {
        if (const char* v = env_or_null(name)) {
            int mb = 0;
            if (parse_int(v, mb, 0, 64 * 1024 * 1024)) out = mb;
        }
    };
    pool_env("R2R_POOL_COMMON_MB", cfg.pool_common_mb);
    pool_env("R2R_POOL_MARKET_MB", cfg.pool_market_mb);
    pool_env("R2R_POOL_PERSONAL_MB", cfg.pool_personal_mb);
    if (const char* v = env_or_null("R2R_MARKET_PRICE_MICRO")) {
        int micro = 0;
        if (parse_int(v, micro, 0, 1000000000)) cfg.market_price_micro = micro;
    }
    if (const char* v = env_or_null("R2R_PAYOUT_ADDRESS")) cfg.payout_address = v;
    if (const char* v = env_or_null("R2R_VAULT_ADDRESS")) cfg.vault_address = v;
    if (const char* v = env_or_null("R2R_CHAIN_ID")) {
        int id = 0;
        if (parse_int(v, id, 1, 1000000000)) cfg.chain_id = id;
    }
    if (const char* v = env_or_null("R2R_PUBLIC_WS_URL")) cfg.public_ws_url = v;
    // The previous relay's TURN settings, so a carried-over unit keeps calls working.
    if (const char* v = env_or_null("TURN_URL")) cfg.turn_url = v;
    if (const char* v = env_or_null("TURN_USER")) cfg.turn_user = v;
    if (const char* v = env_or_null("TURN_PASS")) cfg.turn_pass = v;
    if (const char* v = env_or_null("TURN_SECRET")) cfg.turn_secret = v;
    if (const char* v = env_or_null("TURN_SECRET_FILE")) cfg.turn_secret_file = v;
    if (const char* v = env_or_null("R2R_ADVERTISE")) cfg.advertise = v;
    if (const char* v = env_or_null("R2R_SEEDS"))
        for (auto& s : util::split(v, ','))
            if (!util::trim(s).empty()) cfg.extra_seeds.push_back(util::trim(s));
    if (const char* v = env_or_null("R2R_BIND")) cfg.bind_addr = v;
    if (const char* v = env_or_null("R2R_ALLOW_PRIVATE_PEERS"))
        cfg.allow_private_peers = (std::string(v) == "1" || std::string(v) == "true");
    if (const char* v = env_or_null("R2R_TLS_CERT")) cfg.tls_cert = v;
    if (const char* v = env_or_null("R2R_TLS_KEY")) cfg.tls_key = v;
    if (const char* v = env_or_null("R2R_WS_PORT")) parse_u16(v, cfg.ws_port);
    if (const char* v = env_or_null("R2R_WSS_PORT")) parse_u16(v, cfg.wss_port);
    if (const char* v = env_or_null("R2R_LOG_LEVEL")) {
        if (auto lvl = log::level_from_string(v)) cfg.log_level = *lvl;
    }

    // Compatibility with the environment block the previous relay used, so an
    // existing unit file's settings carry over without being retyped.
    if (const char* v = env_or_null("PORT")) parse_u16(v, cfg.ws_port);
    if (const char* v = env_or_null("DATA_DIR")) cfg.data_dir = v;
    if (const char* v = env_or_null("DEFAULT_QUOTA_MB")) {
        int mb = 0;
        if (parse_int(v, mb, 1, 1024 * 1024)) cfg.default_quota_mb = mb;
    }
    // One retention setting covers both here: payloads are opaque, so the relay
    // cannot tell a voice note from a text message. The longer of the two wins.
    int queue_days = 0, blob_days = 0;
    if (const char* v = env_or_null("QUEUE_TTL_DAYS")) parse_int(v, queue_days, 1, 365);
    if (const char* v = env_or_null("BLOB_TTL_DAYS")) parse_int(v, blob_days, 1, 365);
    if (queue_days || blob_days) cfg.drop_ttl_days = std::max(queue_days, blob_days);
}

std::string usage_text(const char* argv0) {
    std::string s;
    s += "R2R relay " R2R_VERSION " -- privacy-first peer-to-peer messaging relay\n\n";
    s += "Usage: ";
    s += argv0;
    s += " [options]\n\n";
    s +=
        "Listeners\n"
        "  --bind ADDR            Interface to bind (default 0.0.0.0)\n"
        "  --ws-port N            Plaintext ws:// port (default 8787)\n"
        "  --wss-port N           TLS wss:// port (default 8788)\n"
        "  --cert PATH            TLS certificate (default /etc/r2r/tls/cert.pem)\n"
        "  --key PATH             TLS private key (default /etc/r2r/tls/key.pem)\n"
        "  --no-tls               Do not open the wss:// listener\n"
        "\n"
        "Storage\n"
        "  --data-dir PATH        State directory (default /var/lib/r2r)\n"
        "  --peers PATH           peers.json location (default <data-dir>/peers.json)\n"
        "  --db PATH              SQLite database (default <data-dir>/r2r.db)\n"
        "  --node-key PATH        Node seed file (default <data-dir>/node.key)\n"
        "  --assets PATH          Publish this directory under GET /assets/\n"
        "  --doorway PATH         Doorway site bundle (default <data-dir>/doorway)\n"
        "  --base-path P          Mount all HTTP routes under P (e.g. /R2R)\n"
        "  --ttl-days N           Dead-drop retention in days (default 7)\n"
        "\n"
        "Network\n"
        "  --advertise HOST[:PORT]  Address this relay publishes to its peers\n"
        "  --seed HOST:PORT         Extra bootstrap relay (repeatable; env R2R_SEEDS=a,b)\n"
        "  --peer-dial-target N     Outbound peer links to maintain (default 8)\n"
        "  --max-peers N            Peer table ceiling (default 512)\n"
        "  --max-hops N             Forwarding hop limit (default 8)\n"
        "  --no-gossip              Do not exchange peer lists\n"
        "  --allow-private-peers    Accept and dial peers on loopback/private/link-local\n"
        "                           addresses (test benches only; env R2R_ALLOW_PRIVATE_PEERS=1)\n"
        "  --peer-tls-verify        Require a CA-valid certificate from wss:// peers\n"
        "\n"
        "Policy\n"
        "  --open-registration    Register identities without an invite code\n"
        "  --max-payload BYTES    Largest dead-drop payload (default 262144)\n"
        "  --threads N            Worker threads (default: CPU count)\n"
        "  --public-ws-url URL    What cards tell wallets to dial, when a proxy\n"
        "                         terminates TLS (e.g. wss://example.org/ws)\n"
        "  --user NAME            Drop privileges to NAME after binding\n"
        "  --log-level LEVEL      trace|debug|info|warn|error|off (default info)\n"
        "\n"
        "Storage allowances\n"
        "  --pool-common-mb N     Cap on TOTAL storage for default-quota users\n"
        "                         (0 = unlimited; custom-quota users are exempt)\n"
        "  --default-quota-mb N   Storage each user gets by default (default 1)\n"
        "  --set-quota ID MB      Raise (or lower) one user's allowance and exit\n"
        "  --clear-quota ID       Put a user back on the default and exit\n"
        "  --list-quotas          Show every custom allowance and exit\n"
        "\n"
        "Storage market (docs/settlement-design.md; on when --pool-market-mb\n"
        "and --payout-address are both set)\n"
        "  --pool-market-mb N     Bytes budgeted for paid rentals (0 = market off)\n"
        "  --market-price N       micro-USDC per GB-epoch (default 500000 = $0.50)\n"
        "  --payout-address 0x…   Where settled vouchers pay out (bind it on-chain\n"
        "                         with the vault's register())\n"
        "  --vault-address 0x…    The settlement contract, shown to wallets\n"
        "  --chain-id N           EVM chain id (default 8453, Base)\n"
        "  --rent-epoch-days N    Billing epoch (default 31)\n"
        "  --rent-grace-days N    Unpaid first epoch before lapse (default 35)\n"
        "\n"
        "Relay owners (may manage storage from the wallet, no server login)\n"
        "  --owner-add ID         Trust this identity to administer the relay\n"
        "  --owner-remove ID      Withdraw that trust\n"
        "  (ID: the R2R_… address the wallet shows in Settings, or a 64-hex fingerprint)\n"
        "  --list-owners          Show who can administer this relay\n"
        "\n"
        "Administration\n"
        "  --mint-invites N       Print N fresh invite codes and exit\n"
        "  --version              Print version and exit\n"
        "  --help                 Print this help and exit\n"
        "\n"
        "Environment: R2R_DATA_DIR, R2R_PEERS_FILE, R2R_DB_FILE, R2R_ADVERTISE,\n"
        "             R2R_BIND, R2R_TLS_CERT, R2R_TLS_KEY, R2R_WS_PORT,\n"
        "             R2R_WSS_PORT, R2R_LOG_LEVEL, R2R_DOORWAY_DIR, R2R_BASE_PATH,\n"
        "             R2R_PRIMARY_COLOR, R2R_SECONDARY_COLOR\n"
        "Also honoured, for units carried over from the previous relay:\n"
        "             PORT, DATA_DIR, DEFAULT_QUOTA_MB, QUEUE_TTL_DAYS, BLOB_TTL_DAYS\n";
    return s;
}

bool parse_command_line(int argc, char** argv, Config& cfg, int& exit_code) {
    exit_code = 0;
    auto fail = [&](const std::string& msg) {
        std::cerr << "r2r-relay: " << msg << "\n"
                  << "try '" << argv[0] << " --help'\n";
        exit_code = 2;
        return false;
    };

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        auto next = [&](std::string& out) -> bool {
            if (i + 1 >= argc) return false;
            out = argv[++i];
            return true;
        };
        std::string val;

        if (arg == "--help" || arg == "-h") {
            std::cout << usage_text(argv[0]);
            return false;
        }
        if (arg == "--version" || arg == "-V") {
            std::cout << "r2r-relay " R2R_VERSION "\n";
            return false;
        }
        if (arg == "--bind") { if (!next(val)) return fail("--bind needs a value"); cfg.bind_addr = val; }
        else if (arg == "--ws-port") {
            if (!next(val) || !parse_u16(val, cfg.ws_port)) return fail("--ws-port needs a port");
        } else if (arg == "--wss-port") {
            if (!next(val) || !parse_u16(val, cfg.wss_port)) return fail("--wss-port needs a port");
        } else if (arg == "--cert") {
            if (!next(val)) return fail("--cert needs a path");
            cfg.tls_cert = val;
        } else if (arg == "--key") {
            if (!next(val)) return fail("--key needs a path");
            cfg.tls_key = val;
        } else if (arg == "--no-tls") {
            cfg.tls_enabled = false;
        } else if (arg == "--data-dir") {
            if (!next(val)) return fail("--data-dir needs a path");
            cfg.data_dir = val;
        } else if (arg == "--peers") {
            if (!next(val)) return fail("--peers needs a path");
            cfg.peers_file = val;
        } else if (arg == "--db") {
            if (!next(val)) return fail("--db needs a path");
            cfg.db_file = val;
        } else if (arg == "--blob-dir") {
            if (!next(val)) return fail("--blob-dir needs a path");
            cfg.blob_dir = val;
        } else if (arg == "--max-blob") {
            if (!next(val) || !parse_size(val, cfg.max_blob_bytes, 4096, 512u * 1024 * 1024))
                return fail("--max-blob needs 4096..536870912");
        } else if (arg == "--stun") {
            if (!next(val)) return fail("--stun needs a URL");
            cfg.stun_url = val;
        } else if (arg == "--turn") {
            if (!next(val)) return fail("--turn needs a URL");
            cfg.turn_url = val;
        } else if (arg == "--turn-user") {
            if (!next(val)) return fail("--turn-user needs a value");
            cfg.turn_user = val;
        } else if (arg == "--turn-pass") {
            if (!next(val)) return fail("--turn-pass needs a value");
            cfg.turn_pass = val;
        } else if (arg == "--turn-secret") {
            if (!next(val)) return fail("--turn-secret needs a value");
            cfg.turn_secret = val;
        } else if (arg == "--turn-secret-file") {
            if (!next(val)) return fail("--turn-secret-file needs a path");
            cfg.turn_secret_file = val;
        } else if (arg == "--assets") {
            if (!next(val)) return fail("--assets needs a directory");
            cfg.assets_dir = val;
        } else if (arg == "--doorway") {
            if (!next(val)) return fail("--doorway needs a directory");
            cfg.doorway_dir = val;
        } else if (arg == "--base-path") {
            if (!next(val)) return fail("--base-path needs a value like /R2R");
            cfg.base_path = val;
        } else if (arg == "--node-key") {
            if (!next(val)) return fail("--node-key needs a path");
            cfg.node_key_file = val;
        } else if (arg == "--advertise") {
            if (!next(val)) return fail("--advertise needs a value");
            cfg.advertise = val;
        } else if (arg == "--seed") {
            if (!next(val)) return fail("--seed needs HOST:PORT");
            cfg.extra_seeds.push_back(util::trim(val));
        } else if (arg == "--ttl-days") {
            if (!next(val) || !parse_int(val, cfg.drop_ttl_days, 1, 365))
                return fail("--ttl-days needs 1..365");
        } else if (arg == "--threads") {
            if (!next(val) || !parse_int(val, cfg.threads, 1, 256))
                return fail("--threads needs 1..256");
        } else if (arg == "--peer-dial-target") {
            if (!next(val) || !parse_int(val, cfg.peer_dial_target, 0, 128))
                return fail("--peer-dial-target needs 0..128");
        } else if (arg == "--max-hops") {
            if (!next(val) || !parse_int(val, cfg.max_hops, 1, 32))
                return fail("--max-hops needs 1..32");
        } else if (arg == "--max-peers") {
            if (!next(val) || !parse_size(val, cfg.max_peers, 8, 100000))
                return fail("--max-peers needs 8..100000");
        } else if (arg == "--max-payload") {
            if (!next(val) || !parse_size(val, cfg.max_payload_bytes, 1024, 16u * 1024 * 1024))
                return fail("--max-payload needs 1024..16777216");
            cfg.max_frame_bytes = cfg.max_payload_bytes * 2 + 65536;
        } else if (arg == "--no-gossip") {
            cfg.gossip_enabled = false;
        } else if (arg == "--allow-private-peers") {
            cfg.allow_private_peers = true;
        } else if (arg == "--peer-tls-verify") {
            cfg.peer_tls_verify = true;
        } else if (arg == "--open-registration") {
            cfg.require_invite = false;
        } else if (arg == "--user") {
            if (!next(val)) return fail("--user needs a name");
            cfg.run_as_user = val;
        } else if (arg == "--log-level") {
            if (!next(val)) return fail("--log-level needs a value");
            auto lvl = log::level_from_string(val);
            if (!lvl) return fail("unknown log level: " + val);
            cfg.log_level = *lvl;
        } else if (arg == "--mint-invites") {
            if (!next(val) || !parse_int(val, cfg.mint_invites, 1, 1000))
                return fail("--mint-invites needs 1..1000");
        } else if (arg == "--pool-common-mb") {
            int mb = 0;
            if (!next(val) || !parse_int(val, mb, 0, 64 * 1024 * 1024))
                return fail("--pool-common-mb needs 0..67108864");
            cfg.pool_common_mb = mb;
        } else if (arg == "--pool-market-mb") {
            int mb = 0;
            if (!next(val) || !parse_int(val, mb, 0, 64 * 1024 * 1024))
                return fail("--pool-market-mb needs 0..67108864");
            cfg.pool_market_mb = mb;
        } else if (arg == "--pool-personal-mb") {
            int mb = 0;
            if (!next(val) || !parse_int(val, mb, 0, 64 * 1024 * 1024))
                return fail("--pool-personal-mb needs 0..67108864");
            cfg.pool_personal_mb = mb;
        } else if (arg == "--market-price") {
            int micro = 0;
            if (!next(val) || !parse_int(val, micro, 0, 1000000000))
                return fail("--market-price needs micro-USDC per GB-epoch (0..1000000000)");
            cfg.market_price_micro = micro;
        } else if (arg == "--payout-address") {
            if (!next(val)) return fail("--payout-address needs an 0x address");
            cfg.payout_address = util::trim(val);
        } else if (arg == "--vault-address") {
            if (!next(val)) return fail("--vault-address needs an 0x address");
            cfg.vault_address = util::trim(val);
        } else if (arg == "--chain-id") {
            int id = 0;
            if (!next(val) || !parse_int(val, id, 1, 1000000000))
                return fail("--chain-id needs 1..1000000000");
            cfg.chain_id = id;
        } else if (arg == "--rent-epoch-days") {
            if (!next(val) || !parse_int(val, cfg.rent_epoch_days, 1, 365))
                return fail("--rent-epoch-days needs 1..365");
        } else if (arg == "--public-ws-url") {
            if (!next(val)) return fail("--public-ws-url needs a ws:// or wss:// URL");
            cfg.public_ws_url = util::trim(val);
        } else if (arg == "--rent-grace-days") {
            if (!next(val) || !parse_int(val, cfg.rent_grace_days, 0, 365))
                return fail("--rent-grace-days needs 0..365");
        } else if (arg == "--default-quota-mb") {
            int mb = 0;
            if (!next(val) || !parse_int(val, mb, 1, 1024 * 1024))
                return fail("--default-quota-mb needs 1..1048576");
            cfg.default_quota_mb = mb;
        } else if (arg == "--set-quota") {
            std::string fp;
            int mb = 0;
            if (!next(fp)) return fail("--set-quota needs <fingerprint> <MB>");
            if (!next(val) || !parse_int(val, mb, 0, 1024 * 1024))
                return fail("--set-quota needs a size in MB (0..1048576)");
            cfg.quota_target = util::to_lower(util::trim(fp));
            cfg.set_quota_mb = mb;
        } else if (arg == "--clear-quota") {
            if (!next(val)) return fail("--clear-quota needs a fingerprint");
            cfg.quota_target = util::to_lower(util::trim(val));
            cfg.clear_quota = true;
        } else if (arg == "--list-quotas") {
            cfg.show_quotas = true;
        } else if (arg == "--owner-add") {
            if (!next(val)) return fail("--owner-add needs a fingerprint");
            cfg.owner_add = util::to_lower(util::trim(val));
        } else if (arg == "--owner-remove") {
            if (!next(val)) return fail("--owner-remove needs a fingerprint");
            cfg.owner_remove = util::to_lower(util::trim(val));
        } else if (arg == "--list-owners") {
            cfg.show_owners = true;
        } else {
            return fail("unknown option: " + std::string(arg));
        }
    }
    return true;
}

}  // namespace r2r
