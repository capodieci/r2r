// R2R relay -- entry point.
//
// Startup order matters: everything that needs privileges (binding ports,
// reading the TLS key) happens before --user drops them.
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>

#include <algorithm>
#include <cstdio>
#include <exception>
#include <functional>
#include <iostream>
#include <optional>
#include <thread>
#include <vector>

#include "blobstore.hpp"
#include "config.hpp"
#include "crypto.hpp"
#include "db.hpp"
#ifdef R2R_WITH_DOORWAY
#include "doorway.hpp"
#endif
#include "http_routes.hpp"
#include "hub.hpp"
#include "listener.hpp"
#include "log.hpp"
#include "peer_manager.hpp"
#include "peers.hpp"
#include "util.hpp"

namespace {

using namespace r2r;

constexpr int kGenesisInviteCount = 5;

// Codes minted on this relay carry its IPv4 as a routing hint when the
// advertise address is a literal IPv4, so a code redeemed elsewhere can be
// redirected home.
std::string invite_hint(const Config& cfg) {
    if (cfg.advertise.empty()) return {};
    if (auto addr = util::parse_address(cfg.advertise, cfg.ws_port))
        return util::ipv4_hint_hex(addr->host);
    return {};
}

bool drop_privileges(const std::string& user) {
    if (user.empty()) return true;
    if (::geteuid() != 0) {
        log::warn("--user ", user, " ignored: the relay is not running as root");
        return true;
    }
    struct passwd* pw = ::getpwnam(user.c_str());
    if (!pw) {
        log::error("cannot drop privileges: no such user '", user, "'");
        return false;
    }
    if (::setgroups(1, &pw->pw_gid) != 0 || ::setgid(pw->pw_gid) != 0 ||
        ::setuid(pw->pw_uid) != 0) {
        log::error("cannot drop privileges to '", user, "'");
        return false;
    }
    if (::setuid(0) == 0) {  // must fail: the drop has to be irreversible
        log::error("privilege drop did not stick; refusing to continue");
        return false;
    }
    log::info("dropped privileges to user '", user, "'");
    return true;
}

// On a fresh database nobody can join, so mint a first generation of codes and
// leave them in a file only the operator can read. They are deliberately not
// written to the log.
void ensure_genesis_invites(Db& db, const Config& cfg) {
    const auto stats = db.stats();
    if (stats.invites_unused + stats.invites_burned > 0) return;

    auto codes = db.mint_invites(kGenesisInviteCount, "genesis", invite_hint(cfg));
    if (codes.empty()) return;

    std::string body =
        "# R2R genesis invite codes -- each one is single use.\n"
        "# Claiming one registers an identity and returns three fresh codes.\n";
    for (const auto& c : codes) body += c + "\n";

    const std::string path = util::path_join(cfg.data_dir, "genesis-invites.txt");
    if (util::write_file_atomic(path, body, 0600))
        log::info("minted ", codes.size(), " genesis invite codes; they are in ", path);
    else
        log::warn("minted genesis invite codes but could not write ", path);
}

std::string human_bytes(std::int64_t n) {
    char buf[64];
    if (n >= 1024LL * 1024 * 1024)
        std::snprintf(buf, sizeof buf, "%.1f GB", double(n) / (1024.0 * 1024 * 1024));
    else if (n >= 1024 * 1024)
        std::snprintf(buf, sizeof buf, "%.0f MB", double(n) / (1024.0 * 1024));
    else
        std::snprintf(buf, sizeof buf, "%lld B", static_cast<long long>(n));
    return buf;
}

// Admin commands take an identity either as its 64-hex fingerprint or as the
// R2R_… address the wallet shows in Settings (which encodes the public key),
// so an operator never has to derive the fingerprint by hand.
std::optional<std::string> resolve_identity(const std::string& given) {
    const std::string s = util::to_lower(util::trim(given));
    if (util::is_valid_fingerprint(s)) return s;
    if (auto pub = crypto::pubkey_from_contact_address(s)) return crypto::fingerprint(*pub);
    return std::nullopt;
}

// --set-quota / --clear-quota / --list-quotas. These run against the same
// database a live relay is using; SQLite's WAL mode and busy timeout make that
// safe, so an allowance can be changed without restarting the service.
int run_quota_admin(const Config& cfg) {
    Db db;
    if (!db.open(cfg.db_file)) return 1;
    db.set_quota(cfg.max_drops_per_user, cfg.default_quota_mb * 1024 * 1024);

    if (cfg.show_quotas) {
        auto rows = db.list_quotas();
        std::cout << "default allowance: " << human_bytes(cfg.default_quota_mb * 1024 * 1024)
                  << " per user\n";
        if (rows.empty()) {
            std::cout << "no individual allowances set\n";
            return 0;
        }
        std::cout << "\nindividual allowances:\n";
        for (const auto& [fp, bytes] : rows) {
            auto q = db.quota_for(fp);
            std::cout << "  " << fp << "  " << human_bytes(bytes) << "  (using "
                      << human_bytes(q.used_bytes) << " in " << q.used_drops << " payloads)\n";
        }
        return 0;
    }

    const auto resolved = resolve_identity(cfg.quota_target);
    if (!resolved) {
        log::error("'", cfg.quota_target, "' is neither a 64-hex fingerprint nor an R2R_ address");
        return 2;
    }
    const std::string target = *resolved;
    if (target != cfg.quota_target) std::cout << cfg.quota_target << " is fingerprint " << target << "\n";

    if (cfg.clear_quota) {
        if (!db.clear_quota(target)) return 1;
        auto q = db.quota_for(target);
        std::cout << target << " is back on the relay default ("
                  << human_bytes(q.max_bytes) << ")\n";
        return 0;
    }

    const std::int64_t bytes = cfg.set_quota_mb * 1024 * 1024;
    if (!db.set_quota_bytes(target, bytes)) return 1;
    auto q = db.quota_for(target);
    std::cout << target << " may now store " << human_bytes(bytes) << " (currently using "
              << human_bytes(q.used_bytes) << " in " << q.used_drops << " payloads)\n";
    if (q.used_bytes > bytes)
        std::cout << "note: they are already over the new limit; nothing is deleted, but "
                     "further payloads are refused until they collect what is waiting.\n";
    return 0;
}

// --owner-add / --owner-remove / --list-owners. A relay owner is an ordinary
// identity the operator trusts; naming one is the single server-side step that
// then lets them manage the relay from their wallet.
int run_owner_admin(const Config& cfg) {
    Db db;
    if (!db.open(cfg.db_file)) return 1;

    if (cfg.show_owners) {
        auto owners = db.owner_list();
        if (owners.empty()) {
            std::cout << "no owners set. Nobody can administer this relay from a wallet yet.\n"
                      << "Add yourself with:  r2r-relay --owner-add <your fingerprint>\n"
                      << "(paste the R2R_… address your wallet shows in Settings, or the 64-hex fingerprint)\n";
            return 0;
        }
        std::cout << "identities that may administer this relay:\n";
        for (const auto& o : owners) std::cout << "  " << o << "\n";
        return 0;
    }

    const std::string given = cfg.owner_add.empty() ? cfg.owner_remove : cfg.owner_add;
    const auto resolved = resolve_identity(given);
    if (!resolved) {
        log::error("'", given, "' is neither a 64-hex fingerprint nor an R2R_ address");
        return 2;
    }
    const std::string target = *resolved;
    if (target != given) std::cout << given << " is fingerprint " << target << "\n";

    if (!cfg.owner_add.empty()) {
        if (!db.owner_add(target)) return 1;
        std::cout << target << " may now administer this relay from their wallet.\n"
                  << "They will see the owner panel the next time they connect.\n";
        return 0;
    }
    if (!db.owner_remove(target)) return 1;
    std::cout << target << " can no longer administer this relay.\n";
    return 0;
}

int run_mint_invites(const Config& cfg) {
    Db db;
    if (!db.open(cfg.db_file)) return 1;
    auto codes = db.mint_invites(cfg.mint_invites, "operator", invite_hint(cfg));
    for (const auto& c : codes) std::cout << c << "\n";
    std::cout.flush();
    log::info("minted ", codes.size(), " invite codes");
    return codes.empty() ? 1 : 0;
}

}  // namespace

int main(int argc, char** argv) {
    ::signal(SIGPIPE, SIG_IGN);

    Config cfg;
    apply_environment(cfg);
    int exit_code = 0;
    if (!parse_command_line(argc, argv, cfg, exit_code)) return exit_code;
    cfg.finalize();
    log::set_level(cfg.log_level);

    const auto problems = cfg.validate();
    if (!problems.empty()) {
        for (const auto& p : problems) log::error("configuration: ", p);
        return 2;
    }

    try {
        crypto::init();

        if (!util::make_dirs(cfg.data_dir, 0700)) {
            log::error("cannot create the data directory ", cfg.data_dir);
            return 1;
        }

        if (cfg.mint_invites > 0) return run_mint_invites(cfg);
        if (cfg.show_quotas || cfg.clear_quota || cfg.set_quota_mb >= 0)
            return run_quota_admin(cfg);
        if (cfg.show_owners || !cfg.owner_add.empty() || !cfg.owner_remove.empty())
            return run_owner_admin(cfg);

        auto identity = crypto::NodeIdentity::load_or_create(cfg.node_key_file);
        if (!identity) {
            log::error("cannot establish this node's identity");
            return 1;
        }

        Db db;
        if (!db.open(cfg.db_file)) return 1;
        db.set_quota(cfg.max_drops_per_user, cfg.default_quota_mb * 1024 * 1024);
        db.set_common_pool(cfg.pool_common_mb * 1024 * 1024);

        // An owner may have changed the advertised address from their wallet;
        // that choice outlives restarts and wins over the environment.
        if (auto adv = db.meta_get("advertise_override"); adv && !adv->empty()) {
            if (cfg.advertise != *adv)
                log::info("advertise overridden from the admin console: ", *adv,
                          " (environment said '", cfg.advertise, "')");
            cfg.advertise = *adv;
        }

        if (cfg.require_invite) ensure_genesis_invites(db, cfg);

        PeerRegistry peers;
        peers.configure(cfg.peers_file, cfg.max_peers, 3600, cfg.allow_private_peers);
        if (cfg.allow_private_peers)
            log::warn("--allow-private-peers is on: peers on loopback and private ranges "
                      "will be accepted and dialled (test benches only)");
        peers.set_seeds(cfg.extra_seeds);
        peers.set_self(cfg.advertise, identity->node_id(), identity->ed_pub_b64(),
                       identity->x_pub_b64());
        peers.load_or_bootstrap();

        // Declaration order is load-bearing. Live connections are owned by
        // handlers inside the io_context and hold references to the Hub, the
        // ServerContext and the TLS context, so the io_context must be the
        // first of the four to be destroyed -- which means it must be declared
        // last of the four.
        BlobStore blobs;
        if (!blobs.open(cfg.blob_dir)) return 1;

        Hub hub(cfg, db, peers, *identity);
        ServerContext server_ctx{hub, peers, db, blobs, cfg, *identity, util::now_unix()};

        hub.set_blobstore(&blobs);

#ifdef R2R_WITH_DOORWAY
        Doorway doorway;
        if (doorway.load(cfg)) server_ctx.doorway = &doorway;
        hub.set_advertise_hook([&doorway](const std::string& canonical) {
            std::string host = canonical;
            if (auto colon = host.rfind(':'); colon != std::string::npos)
                host = host.substr(0, colon);
            doorway.set_advertise_host(host);
        });
#endif

        std::unique_ptr<ssl::context> tls_ctx;
        if (cfg.tls_enabled) tls_ctx = make_tls_context(cfg);

        const int threads =
            cfg.threads > 0
                ? cfg.threads
                : static_cast<int>(std::max(2u, std::thread::hardware_concurrency()));
        boost::asio::io_context ioc{threads};

        PeerManager peer_manager(ioc, cfg, peers, hub, db, blobs);
        hub.set_dialer(&peer_manager);

        // --- listeners: plaintext always, TLS when the material loaded ------
        auto plain = std::make_shared<Listener>(ioc, server_ctx, nullptr, "ws");
        if (!plain->open(cfg.bind_addr, cfg.ws_port)) return 1;

        std::shared_ptr<Listener> secure;
        if (tls_ctx) {
            secure = std::make_shared<Listener>(ioc, server_ctx, tls_ctx.get(), "wss");
            if (!secure->open(cfg.bind_addr, cfg.wss_port)) {
                log::error("the wss:// listener could not be opened");
                return 1;
            }
        }

        if (!drop_privileges(cfg.run_as_user)) return 1;

        log::info("r2r-relay ", R2R_VERSION, " starting");
        log::info("node ", identity->node_id(), " (", crypto::openssl_version(), ")");
        log::info("data directory ", cfg.data_dir, ", retention ", cfg.drop_ttl_days, " days");
        if (hub.self_address().empty())
            log::warn("this relay does not advertise an address; peers cannot route to it. "
                      "Pass --advertise HOST:PORT to join the network as a routable node.");
        else
            log::info("advertising as ", hub.self_address());

        plain->run();
        if (secure) secure->run();
        peer_manager.start();

        // SIGHUP re-reads the certificate in place. certbot's renewal hook
        // sends it, so a renewed certificate takes effect without restarting
        // the relay and dropping every peer link and client connection.
        boost::asio::signal_set hup(ioc, SIGHUP);
        std::function<void()> await_hup = [&] {
            hup.async_wait([&](const boost::system::error_code& ec, int) {
                if (ec) return;
                if (!tls_ctx) {
                    log::info("SIGHUP received, but this relay is not serving TLS");
                } else if (reload_tls_context(*tls_ctx, cfg)) {
                    log::info("reloaded the TLS certificate from ", cfg.tls_cert);
                } else {
                    log::warn("TLS reload failed; the previous certificate stays in use");
                }
                await_hup();
            });
        };
        await_hup();

        boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code& ec, int sig) {
            if (ec) return;
            log::info("signal ", sig, " received; shutting down");
            plain->stop();
            if (secure) secure->stop();
            peer_manager.stop();
            ioc.stop();
        });

        std::vector<std::thread> pool;
        pool.reserve(static_cast<std::size_t>(threads - 1));
        // Last line of defence: a handler that throws must cost one frame or
        // one connection, never the relay. Input handlers already catch their
        // own errors; this keeps the worker alive if anything slips past.
        auto run_guarded = [&ioc] {
            for (;;) {
                try {
                    ioc.run();
                    return;
                } catch (const std::exception& e) {
                    log::error("handler threw past its guard: ", e.what(), "; continuing");
                } catch (...) {
                    log::error("handler threw a non-standard exception; continuing");
                }
            }
        };
        for (int i = 1; i < threads; ++i) pool.emplace_back(run_guarded);
        log::info("running on ", threads, " threads");
        run_guarded();
        for (auto& t : pool) t.join();

        peers.save();
        db.checkpoint();
        db.close();
        log::info("r2r-relay stopped cleanly");
        return 0;
    } catch (const std::exception& e) {
        log::error("fatal: ", e.what());
        return 1;
    }
}
