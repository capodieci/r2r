#include "protocol.hpp"

#include "config.hpp"
#include "crypto.hpp"
#include "util.hpp"

using nlohmann::json;

namespace r2r {

json build_ice_servers(const Config& cfg, std::string_view identity) {
    json servers = json::array();
    if (!cfg.stun_url.empty()) servers.push_back({{"urls", cfg.stun_url}});
    if (cfg.turn_url.empty()) return servers;

    if (!cfg.turn_secret.empty()) {
        // coturn's REST scheme: the username is its own expiry, and the
        // password is an HMAC of it. Nothing reusable is handed out, and a
        // leaked credential is worthless within minutes.
        const std::int64_t now = util::now_unix();
        std::string username = std::to_string(now + cfg.ice_ttl_seconds);

        if (!identity.empty()) {
            // A daily-rotating handle rather than the fingerprint itself. The
            // TURN server needs *something* stable to apply a per-user limit
            // to, but it has no business knowing who the user is -- and it
            // prints this username in its logs when authentication fails, so
            // anything identifying here ends up on disk. The handle cannot be
            // tied back to an identity without the secret, and stops meaning
            // anything at all after a day.
            const std::string material =
                "turn-handle|" + std::to_string(now / 86400) + "|" + std::string(identity);
            username += ":" + util::hex_encode(crypto::hmac_sha256(cfg.turn_secret, material))
                                  .substr(0, 12);
        }

        const auto mac = crypto::hmac_sha1(cfg.turn_secret, username);
        servers.push_back({{"urls", cfg.turn_url},
                           {"username", username},
                           {"credential", util::b64_encode(mac)}});
    } else {
        servers.push_back({{"urls", cfg.turn_url},
                           {"username", cfg.turn_user},
                           {"credential", cfg.turn_pass}});
    }
    return servers;
}

}  // namespace r2r

namespace r2r::proto {

std::string hello_signing_string(std::string_view node_id, std::string_view advertise,
                                 std::int64_t ts, std::string_view nonce) {
    std::string s = "r2r-hello-v1\n";
    s.append(node_id).append("\n");
    s.append(advertise).append("\n");
    s.append(std::to_string(ts)).append("\n");
    s.append(nonce);
    return s;
}

std::string client_auth_string(std::string_view fingerprint, std::int64_t ts,
                               std::string_view nonce) {
    std::string s = "r2r-client-v1\n";
    s.append(fingerprint).append("\n");
    s.append(std::to_string(ts)).append("\n");
    s.append(nonce);
    return s;
}

std::string pointer_signing_string(std::string_view fingerprint, std::string_view address,
                                   std::int64_t ts) {
    std::string s = "r2r-pointer-v1\n";
    s.append(fingerprint).append("\n");
    s.append(address).append("\n");
    s.append(std::to_string(ts));
    return s;
}

std::string collect_signing_string(std::string_view fingerprint, std::string_view holder,
                                   std::string_view scope, std::int64_t ts,
                                   std::string_view nonce) {
    std::string s = "r2r-collect-v1\n";
    s.append(fingerprint).append("\n");
    s.append(holder).append("\n");
    s.append(scope).append("\n");
    s.append(std::to_string(ts)).append("\n");
    s.append(nonce);
    return s;
}

json make_error(std::string_view code, std::string_view message, std::string_view ref) {
    json j;
    j["t"] = kError;
    j["code"] = std::string(code);
    j["msg"] = std::string(message);
    if (!ref.empty()) j["ref"] = std::string(ref);
    return j;
}

RouteTarget parse_target(std::string_view target) {
    RouteTarget out;
    if (target.empty() || target.size() > 400) return out;

    const auto at = target.find('@');
    std::string_view fp = target;
    if (at != std::string_view::npos) {
        fp = target.substr(0, at);
        const std::string relay = util::trim(target.substr(at + 1));
        if (relay.empty()) return out;
        bool tls = false;
        // Accept "host:port", "ws://host:port" and "wss://host:port".
        std::string s = relay;
        std::uint16_t default_port = 8787;
        const std::string lower = util::to_lower(s);
        if (util::starts_with(lower, "wss://")) { tls = true; default_port = 8788; s = s.substr(6); }
        else if (util::starts_with(lower, "ws://")) { s = s.substr(5); }
        (void)tls;
        auto addr = util::parse_address(s, default_port);
        if (!addr) return out;
        out.relay = addr->str();
    }

    const std::string fingerprint = util::to_lower(util::trim(fp));
    if (!util::is_valid_fingerprint(fingerprint)) return out;
    out.fingerprint = fingerprint;
    out.valid = true;
    return out;
}

}  // namespace r2r::proto
