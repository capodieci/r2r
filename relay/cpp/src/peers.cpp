#include "peers.hpp"

#include <algorithm>
#include <tuple>

#include "config.hpp"
#include "crypto.hpp"
#include "log.hpp"
#include "util.hpp"

using nlohmann::json;

namespace r2r {
namespace {

constexpr int kMaxFailuresBeforePrune = 5;
// Version 2 is the first in which `verified` means "answered a dial of ours".
// Files written by older builds may carry that flag for addresses that only
// ever claimed to be reachable, so it is not trusted from them.
constexpr int kPeersFileVersion = 2;
constexpr std::int64_t kBackoffBaseSeconds = 5;
constexpr std::int64_t kBackoffMaxSeconds = 300;

std::uint64_t random_seed() {
    const auto b = crypto::random_bytes(8);
    std::uint64_t v = 0;
    for (auto x : b) v = (v << 8) | x;
    return v;
}

}  // namespace

std::string PeerInfo::address() const { return util::format_address(host, port); }

std::string PeerInfo::url() const { return (tls ? "wss://" : "ws://") + address(); }

std::int64_t PeerInfo::retry_after() const {
    if (failures <= 0) return 0;
    std::int64_t backoff = kBackoffBaseSeconds;
    for (int i = 1; i < failures && backoff < kBackoffMaxSeconds; ++i) backoff *= 2;
    return last_attempt + std::min(backoff, kBackoffMaxSeconds);
}

PeerRegistry::PeerRegistry() : rng_(random_seed()) {}

void PeerRegistry::configure(std::string file, std::size_t max_peers, std::int64_t prune_after_s,
                             bool allow_private) {
    std::lock_guard<std::mutex> lock(mu_);
    file_ = std::move(file);
    max_peers_ = max_peers;
    prune_after_s_ = prune_after_s;
    allow_private_ = allow_private;
}

bool PeerRegistry::acceptable(std::string_view host) const {
    if (allow_private_) return true;
    return !util::is_non_public_ip(host);
}

void PeerRegistry::set_self(std::string advertise, std::string node_id, std::string ed25519,
                            std::string x25519) {
    std::lock_guard<std::mutex> lock(mu_);
    self_address_ = std::move(advertise);
    self_node_id_ = std::move(node_id);
    self_ed25519_ = std::move(ed25519);
    self_x25519_ = std::move(x25519);
    peers_.erase(self_address_);
}

std::optional<std::string> PeerRegistry::canonicalise(std::string_view input, bool& tls_out) {
    std::string s = util::trim(input);
    std::uint16_t default_port = 0;
    if (util::starts_with(util::to_lower(s), "wss://")) {
        tls_out = true;
        default_port = 8788;
        s = s.substr(6);
    } else if (util::starts_with(util::to_lower(s), "ws://")) {
        tls_out = false;
        default_port = 8787;
        s = s.substr(5);
    } else {
        default_port = tls_out ? 8788 : 8787;
    }
    if (!s.empty() && s.back() == '/') s.pop_back();
    auto addr = util::parse_address(s, default_port);
    if (!addr) return std::nullopt;
    return addr->str();
}

void PeerRegistry::set_seeds(const std::vector<std::string>& extra) {
    std::vector<std::string> all(kSeedPeers, kSeedPeers + kSeedPeerCount);
    all.insert(all.end(), extra.begin(), extra.end());
    std::lock_guard<std::mutex> lock(mu_);
    seeds_.clear();
    for (const auto& s : all) {
        bool tls = false;
        if (auto canon = canonicalise(s, tls))
            if (std::find(seeds_.begin(), seeds_.end(), *canon) == seeds_.end()) seeds_.push_back(*canon);
    }
}

bool PeerRegistry::add(std::string_view address_or_url, bool tls, bool seed) {
    std::lock_guard<std::mutex> lock(mu_);
    return add_locked(address_or_url, tls, seed);
}

bool PeerRegistry::add_locked(std::string_view address_or_url, bool tls, bool seed) {
    bool is_tls = tls;
    auto canon = canonicalise(address_or_url, is_tls);
    if (!canon) return false;
    if (!self_address_.empty() && *canon == self_address_) return false;
    if (self_aliases_.count(*canon)) return false;

    const std::int64_t now = util::now_unix();
    auto it = peers_.find(*canon);
    if (it != peers_.end()) {
        if (seed) it->second.seed = true;
        return false;
    }
    if (peers_.size() >= max_peers_) evict_if_needed();
    if (peers_.size() >= max_peers_ && !seed) return false;

    auto parsed = util::parse_address(*canon, is_tls ? 8788 : 8787);
    if (!parsed) return false;
    if (!allow_private_ && util::is_non_public_ip(parsed->host)) {
        log::debug("refusing non-public peer address ", *canon,
                   " (start with --allow-private-peers to permit it)");
        return false;
    }

    PeerInfo p;
    p.host = parsed->host;
    p.port = parsed->port;
    p.tls = is_tls;
    p.seed = seed;
    p.first_seen = now;
    peers_.emplace(*canon, std::move(p));
    return true;
}

void PeerRegistry::evict_if_needed() {
    if (peers_.size() < max_peers_) return;
    // Drop the least useful non-seed entry: unverified first, then most failures.
    auto worst = peers_.end();
    for (auto it = peers_.begin(); it != peers_.end(); ++it) {
        if (it->second.seed) continue;
        if (worst == peers_.end()) { worst = it; continue; }
        const auto& a = it->second;
        const auto& b = worst->second;
        const auto rank = [](const PeerInfo& p) {
            return std::make_tuple(p.verified ? 1 : 0, -p.failures, p.last_ok);
        };
        if (rank(a) < rank(b)) worst = it;
    }
    if (worst != peers_.end()) peers_.erase(worst);
}

void PeerRegistry::learn_locked(PeerInfo& p, const std::string& node_id,
                                const std::string& ed25519, const std::string& x25519) {
    // Hints only. A pin comes from a handshake on a link this relay opened
    // itself (mark_ok); nothing said by others may touch it.
    if (p.verified) return;
    if (!node_id.empty() && p.node_id.empty()) p.node_id = node_id;
    if (!ed25519.empty() && p.ed25519.empty()) p.ed25519 = ed25519;
    if (!x25519.empty() && p.x25519.empty()) p.x25519 = x25519;
}

std::size_t PeerRegistry::merge(const std::vector<GossipEntry>& entries, std::size_t max_new) {
    std::lock_guard<std::mutex> lock(mu_);
    std::size_t added = 0;
    for (const auto& e : entries) {
        if (!e.node_id.empty() && e.node_id == self_node_id_) continue;
        bool tls = e.tls;
        auto canon = canonicalise(e.address, tls);
        if (!canon) continue;
        auto it = peers_.find(*canon);
        if (it == peers_.end()) {
            if (added >= max_new) continue;
            if (!add_locked(*canon, tls, false)) continue;
            ++added;
            it = peers_.find(*canon);
            if (it == peers_.end()) continue;
        }
        learn_locked(it->second, e.node_id, e.ed25519, e.x25519);
    }
    return added;
}

void PeerRegistry::learn_keys(const std::string& address, const std::string& node_id,
                              const std::string& ed25519, const std::string& x25519) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = peers_.find(address);
    if (it != peers_.end()) learn_locked(it->second, node_id, ed25519, x25519);
}

void PeerRegistry::mark_alive(const std::string& address) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = peers_.find(address);
    if (it == peers_.end() || !it->second.verified) return;
    it->second.last_ok = util::now_unix();
    it->second.failures = 0;
}

std::vector<PeerRegistry::GossipEntry> PeerRegistry::export_gossip(std::size_t max) const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<GossipEntry> out;
    if (!self_address_.empty()) {
        out.push_back({self_address_, false, self_node_id_, self_ed25519_, self_x25519_});
    }
    std::vector<const PeerInfo*> pool;
    pool.reserve(peers_.size());
    for (const auto& [addr, p] : peers_)
        if (p.verified || p.seed) pool.push_back(&p);

    std::shuffle(pool.begin(), pool.end(), rng_);
    for (const auto* p : pool) {
        if (out.size() >= max) break;
        out.push_back({p->address(), p->tls, p->node_id, p->ed25519, p->x25519});
    }
    return out;
}

void PeerRegistry::mark_attempt(const std::string& address) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = peers_.find(address);
    if (it != peers_.end()) it->second.last_attempt = util::now_unix();
}

void PeerRegistry::mark_ok(const std::string& address, const std::string& node_id,
                           const std::string& ed25519, const std::string& x25519) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = peers_.find(address);
    if (it == peers_.end()) {
        if (!add_locked(address, false, false)) return;
        it = peers_.find(address);
        if (it == peers_.end()) return;
    }
    auto& p = it->second;
    p.last_ok = util::now_unix();
    p.failures = 0;
    p.verified = true;
    if (!node_id.empty()) p.node_id = node_id;
    if (!ed25519.empty()) p.ed25519 = ed25519;
    if (!x25519.empty()) p.x25519 = x25519;
}

void PeerRegistry::mark_fail(const std::string& address) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = peers_.find(address);
    if (it == peers_.end()) return;
    it->second.failures += 1;
    it->second.last_attempt = util::now_unix();
}

std::vector<PeerInfo> PeerRegistry::all() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<PeerInfo> out;
    out.reserve(peers_.size());
    for (const auto& [addr, p] : peers_) out.push_back(p);
    return out;
}

std::vector<PeerInfo> PeerRegistry::verified_peers() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<PeerInfo> out;
    for (const auto& [addr, p] : peers_)
        if (p.verified) out.push_back(p);
    return out;
}

std::vector<PeerInfo> PeerRegistry::dial_candidates(std::size_t n,
                                                    const std::set<std::string>& connected) const {
    std::lock_guard<std::mutex> lock(mu_);
    const std::int64_t now = util::now_unix();
    std::vector<PeerInfo> pool;
    for (const auto& [addr, p] : peers_) {
        if (!p.verified && !p.seed) continue;  // unverified ones go through probe_candidates
        if (connected.count(addr)) continue;
        if (p.retry_after() > now) continue;
        pool.push_back(p);
    }
    // Prefer peers we have talked to successfully, then the freshest.
    std::sort(pool.begin(), pool.end(), [](const PeerInfo& a, const PeerInfo& b) {
        if (a.verified != b.verified) return a.verified;
        if (a.failures != b.failures) return a.failures < b.failures;
        return a.last_ok > b.last_ok;
    });
    if (pool.size() > n) pool.resize(n);
    return pool;
}

std::vector<PeerInfo> PeerRegistry::probe_candidates(std::size_t n) const {
    std::lock_guard<std::mutex> lock(mu_);
    const std::int64_t now = util::now_unix();
    std::vector<PeerInfo> pool;
    for (const auto& [addr, p] : peers_) {
        if (p.verified || p.seed) continue;
        if (p.retry_after() > now) continue;
        pool.push_back(p);
    }
    std::sort(pool.begin(), pool.end(), [](const PeerInfo& a, const PeerInfo& b) {
        if (a.last_attempt != b.last_attempt) return a.last_attempt < b.last_attempt;
        return a.first_seen < b.first_seen;
    });
    if (pool.size() > n) pool.resize(n);
    return pool;
}

std::vector<std::string> PeerRegistry::random_addresses(std::size_t n,
                                                        const std::set<std::string>& pool) const {
    std::vector<std::string> out(pool.begin(), pool.end());
    std::lock_guard<std::mutex> lock(mu_);
    std::shuffle(out.begin(), out.end(), rng_);
    if (out.size() > n) out.resize(n);
    return out;
}

std::optional<PeerInfo> PeerRegistry::find(const std::string& address) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = peers_.find(address);
    if (it == peers_.end()) return std::nullopt;
    return it->second;
}

std::optional<PeerInfo> PeerRegistry::find_by_node(const std::string& node_id) const {
    if (node_id.empty()) return std::nullopt;
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto& [addr, p] : peers_)
        if (p.node_id == node_id) return p;
    return std::nullopt;
}

std::size_t PeerRegistry::prune() {
    std::lock_guard<std::mutex> lock(mu_);
    const std::int64_t now = util::now_unix();
    std::size_t removed = 0;
    for (auto it = peers_.begin(); it != peers_.end();) {
        const PeerInfo& p = it->second;
        bool drop = false;
        if (!p.seed && p.failures >= kMaxFailuresBeforePrune) {
            const std::int64_t reference = p.last_ok ? p.last_ok : p.first_seen;
            drop = (now - reference) > prune_after_s_;
        }
        if (drop) {
            log::info("pruning unresponsive peer ", it->first, " (", p.failures, " failures)");
            it = peers_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

std::size_t PeerRegistry::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return peers_.size();
}

std::size_t PeerRegistry::verified_count() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::size_t n = 0;
    for (const auto& [addr, p] : peers_)
        if (p.verified) ++n;
    return n;
}

bool PeerRegistry::is_self(std::string_view address) const {
    std::lock_guard<std::mutex> lock(mu_);
    return !self_address_.empty() && self_address_ == address;
}

bool PeerRegistry::is_self_node(std::string_view node_id) const {
    std::lock_guard<std::mutex> lock(mu_);
    return !self_node_id_.empty() && self_node_id_ == node_id;
}

void PeerRegistry::mark_self_alias(const std::string& address) {
    bool tls = false;
    auto canon = canonicalise(address, tls);
    if (!canon) return;
    std::lock_guard<std::mutex> lock(mu_);
    if (self_aliases_.insert(*canon).second)
        log::info("address ", *canon, " is this relay itself; removing it from the peer table");
    peers_.erase(*canon);
}

// ------------------------------------------------------------ peers.json ---

json PeerRegistry::to_file_json() const {
    std::lock_guard<std::mutex> lock(mu_);
    json doc;
    doc["version"] = kPeersFileVersion;
    doc["updated_at"] = util::now_unix();
    doc["node"] = {{"id", self_node_id_},
                   {"advertise", self_address_},
                   {"ed25519", self_ed25519_},
                   {"x25519", self_x25519_}};
    json arr = json::array();
    for (const auto& [addr, p] : peers_) {
        arr.push_back({{"address", addr},
                       {"tls", p.tls},
                       {"seed", p.seed},
                       {"verified", p.verified},
                       {"node_id", p.node_id},
                       {"ed25519", p.ed25519},
                       {"x25519", p.x25519},
                       {"first_seen", p.first_seen},
                       {"last_ok", p.last_ok},
                       {"failures", p.failures}});
    }
    doc["peers"] = std::move(arr);
    return doc;
}

json PeerRegistry::to_public_json() const {
    std::lock_guard<std::mutex> lock(mu_);
    json doc;
    doc["version"] = 1;
    doc["updated_at"] = util::now_unix();
    doc["node"] = {{"id", self_node_id_},
                   {"advertise", self_address_},
                   {"ed25519", self_ed25519_},
                   {"x25519", self_x25519_}};
    json arr = json::array();
    for (const auto& [addr, p] : peers_) {
        if (!p.verified && !p.seed) continue;  // only publish what we trust
        arr.push_back({{"address", addr},
                       {"url", p.url()},
                       {"tls", p.tls},
                       {"verified", p.verified},
                       {"node_id", p.node_id},
                       {"x25519", p.x25519},
                       {"last_ok", p.last_ok}});
    }
    doc["peers"] = std::move(arr);
    doc["count"] = doc["peers"].size();
    return doc;
}

bool PeerRegistry::save() {
    std::string file;
    {
        std::lock_guard<std::mutex> lock(mu_);
        file = file_;
    }
    if (file.empty()) return false;
    const std::string text = to_file_json().dump(2) + "\n";
    if (!util::make_dirs(util::dirname_of(file), 0700)) return false;
    if (!util::write_file_atomic(file, text, 0600)) {
        log::error("failed to write ", file);
        return false;
    }
    return true;
}

bool PeerRegistry::load_or_bootstrap() {
    std::string file;
    {
        std::lock_guard<std::mutex> lock(mu_);
        file = file_;
    }

    auto bootstrap = [&] {
        std::size_t n = 0;
        std::vector<std::string> seeds;
        {
            std::lock_guard<std::mutex> lock(mu_);
            seeds = seeds_;
        }
        for (const auto& s : seeds)
            if (add(s, false, true)) ++n;
        log::info("bootstrapped peer table with ", n, " seed nodes");
        save();
    };

    auto raw = util::read_file(file);
    if (!raw) {
        log::info("no peers.json at ", file, "; seeding from the built-in bootstrap list");
        bootstrap();
        return true;
    }

    json doc = json::parse(*raw, nullptr, false);
    if (doc.is_discarded()) {
        log::warn(file, " is not valid JSON; re-seeding from the bootstrap list");
        bootstrap();
        return true;
    }

    const json* list = nullptr;
    int file_version = 0;
    if (doc.is_array()) {
        list = &doc;
    } else if (doc.is_object() && doc.contains("peers") && doc["peers"].is_array()) {
        list = &doc["peers"];
        file_version = doc.value("version", 1);
    }
    const bool trust_verified = file_version >= kPeersFileVersion;
    if (list && !trust_verified)
        log::info(file, " predates the current peer-verification rules; every peer will be "
                        "re-verified by dialling it");
    if (!list) {
        log::warn(file, " has no peer list; re-seeding from the bootstrap list");
        bootstrap();
        return true;
    }

    std::size_t loaded = 0;
    for (const auto& item : *list) try {
        std::string address;
        bool tls = false;
        PeerInfo hint;
        if (item.is_string()) {
            address = item.get<std::string>();
        } else if (item.is_object()) {
            if (item.contains("address") && item["address"].is_string())
                address = item["address"].get<std::string>();
            else if (item.contains("url") && item["url"].is_string())
                address = item["url"].get<std::string>();
            if (item.value("tls", false)) tls = true;
            // Seed status comes from the configured list, never from the
            // file: a relay dropped from the network must be able to age out.
            hint.seed = false;
            hint.verified = trust_verified && item.value("verified", false);
            hint.node_id = item.value("node_id", std::string{});
            hint.ed25519 = item.value("ed25519", std::string{});
            hint.x25519 = item.value("x25519", std::string{});
            hint.first_seen = item.value("first_seen", std::int64_t{0});
            hint.last_ok = item.value("last_ok", std::int64_t{0});
            hint.failures = item.value("failures", 0);
        }
        if (address.empty()) continue;

        bool tls_flag = tls;
        auto canon = canonicalise(address, tls_flag);
        if (!canon) {
            log::warn("ignoring malformed peer entry in ", file);
            continue;
        }
        if (!add(*canon, tls_flag, hint.seed)) {
            // already present (or self) -- nothing more to do
        }
        std::lock_guard<std::mutex> lock(mu_);
        auto it = peers_.find(*canon);
        if (it == peers_.end()) {
            if (auto a = util::parse_address(*canon, 8787); a && !acceptable(a->host))
                log::warn("ignoring non-public peer ", *canon, " in ", file,
                          " (start with --allow-private-peers to keep it)");
            continue;
        }
        auto& p = it->second;
        if (!hint.node_id.empty()) p.node_id = hint.node_id;
        if (!hint.ed25519.empty()) p.ed25519 = hint.ed25519;
        if (!hint.x25519.empty()) p.x25519 = hint.x25519;
        if (hint.first_seen) p.first_seen = hint.first_seen;
        p.last_ok = hint.last_ok;
        p.failures = hint.failures;
        p.verified = hint.verified;
        ++loaded;
    } catch (const json::exception&) {
        log::warn("ignoring a peer entry with wrong-typed fields in ", file);
    }

    // Seeds are always present, even if an operator removed them by hand.
    std::vector<std::string> seeds;
    {
        std::lock_guard<std::mutex> lock(mu_);
        seeds = seeds_;
    }
    for (const auto& s : seeds) add(s, false, true);

    log::info("loaded ", loaded, " peers from ", file, " (table now holds ", size(), ")");
    return true;
}

}  // namespace r2r
