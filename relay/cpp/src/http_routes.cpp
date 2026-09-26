#include "http_routes.hpp"

#include <cctype>
#include <cstring>
#include <map>
#include <mutex>

#include <nlohmann/json.hpp>

#ifdef R2R_WITH_ADMIN_UI
#include "admin_ui.hpp"
#endif
#ifdef R2R_WITH_DOORWAY
#include "doorway.hpp"
#endif
#include "log.hpp"
#include "protocol.hpp"
#include "util.hpp"

using nlohmann::json;

namespace r2r {
namespace {

// A Host header value that is safe to echo: it must parse as an address
// (letters, digits, dots, dashes, underscores, one optional port, or a
// bracketed IPv6 literal). Everything else becomes empty, which the doorway
// treats as "use the advertise host". No HTML metacharacter survives this.
std::string safe_host(std::string raw) {
    raw = r2r::util::trim(raw);
    if (raw.empty() || raw.size() > 253 + 6) return {};
    auto a = r2r::util::parse_address(raw, 1);
    if (!a) return {};
    return r2r::util::to_lower(raw);
}


using Response = http::response<http::string_body>;
using Request = http::request<http::string_body>;

void common_headers(Response& res) {
    res.set(http::field::server, "r2r-relay/" R2R_VERSION);
    res.set("X-Content-Type-Options", "nosniff");
    res.set("Referrer-Policy", "no-referrer");
    res.set("X-Frame-Options", "DENY");
    // The relay keeps no logs; asking intermediaries not to keep any either.
    res.set(http::field::cache_control, "no-store");
}

void cors_headers(Response& res) {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type");
    res.set("Access-Control-Max-Age", "600");
}

Response finish(Response res, const Request& req, std::string body, const char* content_type) {
    common_headers(res);
    res.set(http::field::content_type, content_type);
    res.keep_alive(req.keep_alive());
    if (req.method() == http::verb::head) {
        res.content_length(body.size());
        res.body().clear();
    } else {
        res.body() = std::move(body);
        res.prepare_payload();
    }
    return res;
}

Response json_response(const Request& req, http::status status, const json& j) {
    Response res{status, req.version()};
    cors_headers(res);
    return finish(std::move(res), req, j.dump(2) + "\n", "application/json; charset=utf-8");
}

Response text_response(const Request& req, http::status status, std::string body) {
    Response res{status, req.version()};
    return finish(std::move(res), req, std::move(body), "text/plain; charset=utf-8");
}

Response html_response(const Request& req, http::status status, std::string body) {
    Response res{status, req.version()};
    res.set("Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'");
    return finish(std::move(res), req, std::move(body), "text/html; charset=utf-8");
}

// Minimal x-www-form-urlencoded / query-string field lookup.
std::string decode_component(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '+') {
            out += ' ';
        } else if (s[i] == '%' && i + 2 < s.size() && std::isxdigit((unsigned char)s[i + 1]) &&
                   std::isxdigit((unsigned char)s[i + 2])) {
            auto hex = [](char c) {
                return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
            };
            out += static_cast<char>(hex(s[i + 1]) * 16 + hex(s[i + 2]));
            i += 2;
        } else {
            out += s[i];
        }
    }
    return out;
}

std::string param_from(std::string_view pairs, std::string_view name) {
    std::size_t pos = 0;
    while (pos <= pairs.size()) {
        const std::size_t amp = std::min(pairs.find('&', pos), pairs.size());
        const std::string_view pair = pairs.substr(pos, amp - pos);
        const std::size_t eq = pair.find('=');
        if (eq != std::string_view::npos && pair.substr(0, eq) == name)
            return decode_component(pair.substr(eq + 1));
        pos = amp + 1;
    }
    return {};
}

std::string url_encode(std::string_view s) {
    static const char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out += static_cast<char>(c);
        else { out += '%'; out += kHex[c >> 4]; out += kHex[c & 15]; }
    }
    return out;
}

std::string query_param(std::string_view target, std::string_view name) {
    const auto q = target.find('?');
    if (q == std::string_view::npos) return {};
    return param_from(target.substr(q + 1), name);
}

std::string path_of(std::string_view target) {
    const auto q = target.find('?');
    std::string path(q == std::string_view::npos ? target : target.substr(0, q));
    if (path.empty()) path = "/";
    // Collapse a trailing slash so /health/ and /health are the same route.
    if (path.size() > 1 && path.back() == '/') path.pop_back();
    return path;
}

const char* content_type_for(std::string_view name) {
    auto ends = [&](std::string_view ext) {
        return name.size() > ext.size() &&
               util::iequals(name.substr(name.size() - ext.size()), ext);
    };
    if (ends(".json")) return "application/json; charset=utf-8";
    if (ends(".txt") || ends(".asc") || ends(".sig")) return "text/plain; charset=utf-8";
    if (ends(".md")) return "text/markdown; charset=utf-8";
    if (ends(".html")) return "text/html; charset=utf-8";
    if (ends(".png")) return "image/png";
    if (ends(".svg")) return "image/svg+xml";
    if (ends(".pdf")) return "application/pdf";
    if (ends(".zip")) return "application/zip";
    if (ends(".gz") || ends(".tgz")) return "application/gzip";
    if (ends(".xz")) return "application/x-xz";
    return "application/octet-stream";
}

// SHA-256 of a published file, remembered until the file changes, so a client
// can verify a download without the relay hashing it on every request.
std::string asset_digest(const std::string& path, const util::DirEntry& entry) {
    static std::mutex mu;
    static std::map<std::string, std::pair<std::string, std::string>> cache;  // name -> {stamp,hash}
    const std::string stamp = std::to_string(entry.mtime) + ":" + std::to_string(entry.size);
    {
        std::lock_guard<std::mutex> lock(mu);
        auto it = cache.find(entry.name);
        if (it != cache.end() && it->second.first == stamp) return it->second.second;
    }
    auto body = util::read_file(path);
    if (!body) return {};
    const std::string hash = util::hex_encode(crypto::sha256(*body));
    std::lock_guard<std::mutex> lock(mu);
    cache[entry.name] = {stamp, hash};
    return hash;
}

// GET /assets/           -> a signed-by-nothing manifest: name, size, sha256
// GET /assets/<name>     -> the file itself
//
// Only regular files directly inside the configured directory are reachable:
// the request name must be a single safe component, so there is no path to
// traverse out of.
Response serve_asset(const Request& req, ServerContext& ctx, const std::string& path) {
    if (ctx.cfg.assets_dir.empty())
        return json_response(req, http::status::not_found,
                             json{{"ok", false}, {"error", "assets_disabled"}});

    std::string name = path.substr(std::strlen("/assets"));
    if (!name.empty() && name.front() == '/') name.erase(0, 1);

    if (name.empty()) {
        json files = json::array();
        for (const auto& e : util::list_files(ctx.cfg.assets_dir)) {
            if (static_cast<std::size_t>(e.size) > ctx.cfg.max_asset_bytes) continue;
            files.push_back({{"name", e.name},
                             {"size", e.size},
                             {"modified", e.mtime},
                             {"sha256", asset_digest(util::path_join(ctx.cfg.assets_dir, e.name), e)},
                             {"url", ctx.cfg.base_path + "/assets/" + e.name}});
        }
        return json_response(req, http::status::ok,
                             json{{"ok", true}, {"count", files.size()}, {"assets", files}});
    }

    if (!util::is_safe_filename(name))
        return json_response(req, http::status::bad_request,
                             json{{"ok", false}, {"error", "bad_name"}});

    const std::string full = util::path_join(ctx.cfg.assets_dir, name);
    auto body = util::read_file(full);
    if (!body)
        return json_response(req, http::status::not_found,
                             json{{"ok", false}, {"error", "not_found"}});
    if (body->size() > ctx.cfg.max_asset_bytes)
        return json_response(req, http::status::payload_too_large,
                             json{{"ok", false}, {"error", "too_large"}});

    const char* type = content_type_for(name);
    Response res{http::status::ok, req.version()};
    cors_headers(res);
    res.set("X-Content-Sha256", util::hex_encode(crypto::sha256(*body)));
    if (std::string(type) == "application/octet-stream")
        res.set(http::field::content_disposition, "attachment; filename=\"" + name + "\"");
    return finish(std::move(res), req, std::move(*body), type);
}

// Clients authenticate HTTP requests with the same signed proof they put in a
// `hello` frame, base64-encoded into a header. Reusing one shape means one
// verification path and one thing for a client to get right.
std::optional<Hub::ClientProof> header_auth(const Request& req, ServerContext& ctx) {
    auto it = req.find("X-R2R-Auth");
    if (it == req.end()) return std::nullopt;
    auto raw = util::b64_decode(std::string(it->value()));
    if (!raw || raw->size() > 4096) return std::nullopt;
    auto j = json::parse(raw->begin(), raw->end(), nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;
    auto proof = ctx.hub.verify_client_proof(j);
    if (!proof.ok) return std::nullopt;
    return proof;
}

Response unauthorised(const Request& req) {
    return json_response(req, http::status::unauthorized,
                         json{{"ok", false}, {"error", proto::kErrNotAuthorised}});
}

// POST /blob -- a recorded voice or video message. The bytes are ciphertext;
// the id is their SHA-256, so the same recording sent to five people is stored
// once and any client can verify what it downloaded.
Response put_blob(const Request& req, ServerContext& ctx) {
    auto proof = header_auth(req, ctx);
    if (!proof) return unauthorised(req);

    const auto& body = req.body();
    if (body.empty())
        return json_response(req, http::status::bad_request,
                             json{{"ok", false}, {"error", "empty"}});
    if (body.size() > ctx.cfg.max_blob_bytes)
        return json_response(req, http::status::payload_too_large,
                             json{{"ok", false}, {"error", proto::kErrTooBig},
                                  {"max_bytes", ctx.cfg.max_blob_bytes}});

    auto id = ctx.blobs.put(body.data(), body.size());
    if (!id)
        return json_response(req, http::status::internal_server_error,
                             json{{"ok", false}, {"error", proto::kErrInternal}});

    const std::int64_t expires =
        util::now_unix() +
        ctx.db.ttl_days_for(proof->fingerprint, ctx.cfg.drop_ttl_days) * 86400;
    const auto rc = ctx.db.blob_record(*id, proof->fingerprint,
                                       static_cast<std::int64_t>(body.size()), expires);
    if (rc == Db::BlobResult::quota_exceeded) {
        // The bytes may be shared with another owner, so they are not deleted
        // here; the sweep removes them if this was the only reference.
        return json_response(req, http::status::payload_too_large,
                             json{{"ok", false}, {"error", proto::kErrQuota}});
    }
    if (rc == Db::BlobResult::error)
        return json_response(req, http::status::internal_server_error,
                             json{{"ok", false}, {"error", proto::kErrInternal}});

    return json_response(req, http::status::ok,
                         json{{"ok", true}, {"id", *id}, {"size", body.size()},
                              {"expires_at", expires},
                              {"duplicate", rc == Db::BlobResult::duplicate}});
}

Response get_blob(const Request& req, ServerContext& ctx, const std::string& path) {
    auto proof = header_auth(req, ctx);
    if (!proof) return unauthorised(req);

    const std::string id = util::to_lower(path.substr(std::strlen("/blob/")));
    if (!BlobStore::is_valid_id(id))
        return json_response(req, http::status::bad_request,
                             json{{"ok", false}, {"error", "bad_id"}});
    // Anyone holding the id may fetch it. The id is the hash of ciphertext
    // only the intended recipient can decrypt, and it travels inside an
    // end-to-end encrypted message.
    if (!ctx.db.blob_exists(id))
        return json_response(req, http::status::not_found,
                             json{{"ok", false}, {"error", "gone"}});
    auto bytes = ctx.blobs.get(id);
    if (!bytes)
        return json_response(req, http::status::not_found,
                             json{{"ok", false}, {"error", "gone"}});

    Response res{http::status::ok, req.version()};
    cors_headers(res);
    res.set("X-Content-Sha256", id);
    return finish(std::move(res), req, std::string(bytes->begin(), bytes->end()),
                  "application/octet-stream");
}

std::string landing_page(ServerContext& ctx, const Hub::Stats& hs, const Db::Stats& ds,
                         std::int64_t uptime) {
    const std::size_t active_nodes = ctx.peers.verified_count();
    const std::size_t known_nodes = ctx.peers.size();

    auto row = [](std::string_view label, const std::string& value) {
        return "<div class=\"row\"><span class=\"k\">" + std::string(label) +
               "</span><span class=\"v\">" + util::html_escape(value) + "</span></div>";
    };

    std::string html;
    html.reserve(6000);
    html +=
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<meta name=\"robots\" content=\"noindex,nofollow\">"
        "<meta http-equiv=\"refresh\" content=\"30\">"
        "<title>R2R relay</title><style>"
        ":root{color-scheme:light dark;--bg:#fbfbfd;--fg:#16181d;--mut:#6b7280;"
        "--line:#e4e4e9;--card:#fff;--acc:#2f6f4f}"
        "@media(prefers-color-scheme:dark){:root{--bg:#0e1013;--fg:#e8e9ec;--mut:#9aa1ab;"
        "--line:#23262d;--card:#15181d;--acc:#79d0a3}}"
        "*{box-sizing:border-box}"
        "body{margin:0;padding:2.5rem 1.25rem;background:var(--bg);color:var(--fg);"
        "font:15px/1.55 ui-sans-serif,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}"
        "main{max-width:46rem;margin:0 auto}"
        "h1{font-size:1.4rem;margin:0 0 .2rem;letter-spacing:-.01em}"
        "p.sub{margin:0 0 1.75rem;color:var(--mut);font-size:.92rem}"
        ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(9.5rem,1fr));gap:.75rem;"
        "margin-bottom:1.75rem}"
        ".stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:.9rem 1rem}"
        ".stat .n{font-size:1.5rem;font-weight:600;letter-spacing:-.02em}"
        ".stat .l{color:var(--mut);font-size:.78rem;text-transform:uppercase;letter-spacing:.06em;"
        "margin-top:.15rem}"
        "section{background:var(--card);border:1px solid var(--line);border-radius:10px;"
        "padding:.35rem 1rem;margin-bottom:1.25rem}"
        "h2{font-size:.78rem;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);"
        "margin:1rem 0 .6rem}"
        ".row{display:flex;justify-content:space-between;gap:1rem;padding:.42rem 0;"
        "border-top:1px solid var(--line);font-size:.9rem}"
        ".row:first-of-type{border-top:none}"
        ".k{color:var(--mut)}.v{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;"
        "text-align:right;word-break:break-all}"
        "a{color:var(--acc)}"
        "footer{color:var(--mut);font-size:.82rem;margin-top:1.5rem}"
        "</style></head><body><main>";

    html += "<h1>R2R relay</h1><p class=\"sub\">Privacy-first peer-to-peer messaging relay. "
            "This node stores encrypted payloads it cannot read, and keeps no IP logs.</p>";

    auto stat = [&](std::int64_t n, std::string_view label) {
        html += "<div class=\"stat\"><div class=\"n\">" + std::to_string(n) +
                "</div><div class=\"l\">" + std::string(label) + "</div></div>";
    };
    html += "<div class=\"grid\">";
    stat(static_cast<std::int64_t>(active_nodes), "active nodes");
    stat(ds.drops_stored, "payloads held");
    stat(static_cast<std::int64_t>(hs.connections), "live connections");
    stat(hs.forwarded, "frames relayed");
    html += "</div>";

    html += "<h2>Network</h2><section>";
    html += row("uptime", util::human_duration(uptime));
    html += row("node id", ctx.node.node_id());
    html += row("advertised as", ctx.hub.self_address().empty() ? "(not advertised)"
                                                                : ctx.hub.self_address());
    html += row("peers known / verified",
                std::to_string(known_nodes) + " / " + std::to_string(active_nodes));
    html += row("relay links", std::to_string(hs.relay_links));
    html += row("client connections", std::to_string(hs.clients));
    html += row("ws:// port", std::to_string(ctx.cfg.ws_port));
    html += row("wss:// port",
                ctx.cfg.tls_enabled ? std::to_string(ctx.cfg.wss_port) : "disabled");
    html += "</section>";

    html += "<h2>Dead drops</h2><section>";
    html += row("payloads stored", std::to_string(ds.drops_stored));
    html += row("bytes held", std::to_string(ds.drop_bytes));
    html += row("retention", std::to_string(ctx.cfg.drop_ttl_days) + " days");
    html += row("accepted / rejected",
                std::to_string(hs.drops_accepted) + " / " + std::to_string(hs.drops_rejected));
    html += row("onion layers peeled", std::to_string(hs.onion_peeled));
    html += row("registered identities", std::to_string(ds.identities));
    html += "</section>";

    const std::string& bp = ctx.cfg.base_path;
    html += "<h2>Endpoints</h2><section>";
    html += "<div class=\"row\"><span class=\"k\">peer list</span><span class=\"v\">"
            "<a href=\"" + bp + "/peers.json\">" + bp + "/peers.json</a></span></div>";
    html += "<div class=\"row\"><span class=\"k\">node keys</span><span class=\"v\">"
            "<a href=\"" + bp + "/node.json\">" + bp + "/node.json</a></span></div>";
    html += "<div class=\"row\"><span class=\"k\">counters</span><span class=\"v\">"
            "<a href=\"" + bp + "/status.json\">" + bp + "/status.json</a></span></div>";
    if (!ctx.cfg.assets_dir.empty())
        html += "<div class=\"row\"><span class=\"k\">downloads</span><span class=\"v\">"
                "<a href=\"" + bp + "/assets/\">" + bp + "/assets/</a></span></div>";
    html += "</section>";

    html += "<footer>r2r-relay " R2R_VERSION " &middot; no personal data, no IP logs, "
            "payloads expire automatically.</footer>";
    html += "</main></body></html>\n";
    return html;
}

}  // namespace

http::response<http::string_body> handle_http_request(const Request& req, ServerContext& ctx,
                                                      bool secure) {
    // A TLS-terminating proxy in front of the plain listener says so here.
    // Nothing security-relevant keys on `secure` -- it only picks the scheme
    // rendered into links -- so trusting the header is safe.
    if (!secure) {
        auto xf = req.find("X-Forwarded-Proto");
        if (xf != req.end() && xf->value() == "https") secure = true;
    }
    std::string path = path_of(req.target());
    // Mounted under a prefix (R2R_BASE_PATH=/R2R): strip it and route as
    // usual. Unprefixed requests still work, for local and debug access.
    // Invite short-URLs never collide: "/R2R-…" has a dash where the mount
    // point has a slash (or nothing).
    if (const std::string& bp = ctx.cfg.base_path; !bp.empty()) {
        if (path == bp) path = "/";
        else if (util::starts_with(path, bp + "/")) path.erase(0, bp.size());
    }
    const auto method = req.method();
    const std::int64_t uptime = util::now_unix() - ctx.started_at;

    if (method == http::verb::options) {
        Response res{http::status::no_content, req.version()};
        cors_headers(res);
        common_headers(res);
        res.keep_alive(req.keep_alive());
        return res;
    }

    const bool readable = (method == http::verb::get || method == http::verb::head);

#ifdef R2R_WITH_ADMIN_UI
    // The owner console. Independent of the doorway: the adminOnly profile
    // serves it with no public site at all. Auth happens inside — the page
    // signs the same owner-gated frames a wallet would.
    if (readable && path == "/admin") {
        std::string html = admin_ui::html();
        const std::string token = "{{BASE}}";
        std::size_t pos = 0;
        while ((pos = html.find(token, pos)) != std::string::npos) {
            html.replace(pos, token.size(), ctx.cfg.base_path);
            pos += ctx.cfg.base_path.size();
        }
        Response res{http::status::ok, req.version()};
        res.set("Content-Security-Policy",
                "default-src 'none'; script-src 'self' 'unsafe-inline'; "
                "style-src 'unsafe-inline'; connect-src 'self' ws: wss:; "
                "base-uri 'none'; frame-ancestors 'none'");
        res.set("X-Robots-Tag", "noindex,nofollow");
        return finish(std::move(res), req, std::move(html), "text/html; charset=utf-8");
    }
    if (readable && path == "/admin/nacl.js") {
        Response res{http::status::ok, req.version()};
        auto out = finish(std::move(res), req, admin_ui::nacl_js(),
                          "application/javascript; charset=utf-8");
        out.set(http::field::cache_control, "public, max-age=86400, immutable");
        return out;
    }
#endif

#ifdef R2R_WITH_DOORWAY
    // The doorway site takes over "/" and its page routes when a bundle is
    // loaded; every JSON endpoint below keeps its route either way.
    if (ctx.doorway && ctx.doorway->loaded()) {
        // The Host header is attacker-influenced behind a careless proxy or
        // cache. Only a plain hostname[:port] (or [v6]:port) is ever used;
        // anything else falls back to the advertise host inside the doorway.
        const std::string host = safe_host(std::string(req[http::field::host]));
        std::string lang = ctx.doorway->pick_language(
            std::string(req[http::field::cookie]),
            std::string(req[http::field::accept_language]));
        // The topbar's language switcher submits ?lang=xx: a valid choice
        // wins over cookie and Accept-Language and is persisted in the
        // cookie the next pick_language reads.
        std::string lang_cookie;
        if (std::string q = query_param(req.target(), "lang"); !q.empty()) {
            q = util::to_lower(util::trim(q));
            if (ctx.doorway->has_language(q)) {
                lang = q;
                lang_cookie = "lang=" + q + "; Path=/; Max-Age=31536000; SameSite=Lax";
            }
        }
        const std::string& base = ctx.cfg.base_path;
        const std::string scheme = secure ? "https" : "http";

        // The address a wallet should dial, shown on cards and contact pages.
        // Reads the hub's live advertise so admin_set_advertise takes effect
        // without a restart.
        auto ws_url = [&]() {
            if (!ctx.cfg.public_ws_url.empty()) return ctx.cfg.public_ws_url;
            std::string h;
            if (auto a = util::parse_address(ctx.hub.self_address(), ctx.cfg.ws_port)) h = a->host;
            if (h.empty()) {
                h = host;
                if (auto colon = h.rfind(':'); colon != std::string::npos) h = h.substr(0, colon);
            }
            return ctx.cfg.tls_enabled
                       ? "wss://" + h + ":" + std::to_string(ctx.cfg.wss_port)
                       : "ws://" + h + ":" + std::to_string(ctx.cfg.ws_port);
        };
        auto our_ip = [&]() {
            if (auto a = util::parse_address(ctx.hub.self_address(), ctx.cfg.ws_port))
                return a->host;
            return std::string{};
        };
        auto redirect = [&](const std::string& location) {
            Response res{http::status::found, req.version()};
            res.set(http::field::location, location);
            common_headers(res);
            res.keep_alive(req.keep_alive());
            res.prepare_payload();
            return res;
        };
        auto doorway_html = [&](std::string html, const char* csp) {
            Response res{http::status::ok, req.version()};
            res.set("Content-Security-Policy", csp);
            res.set("X-Robots-Tag", "noindex,nofollow");
            auto out = finish(std::move(res), req, std::move(html), "text/html; charset=utf-8");
            out.set(http::field::cache_control, "no-store");
            if (!lang_cookie.empty()) out.set(http::field::set_cookie, lang_cookie);
            return out;
        };
        static constexpr const char* kCspDynamic =
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'";

        if (readable) {
            // Root-level statics and /js/*, exactly the paths the pages link.
            std::string asset_rel;
            if (path == "/sippis-shell.css" || path == "/favicon.svg" ||
                path == "/favicon.ico" || path == "/sippis-logo.svg")
                asset_rel = path.substr(1);
            else if (util::starts_with(path, "/js/"))
                asset_rel = path.substr(1);
            if (!asset_rel.empty()) {
                if (auto a = ctx.doorway->asset(asset_rel)) {
                    Response res{http::status::ok, req.version()};
                    auto out = finish(std::move(res), req, std::move(a->bytes),
                                      a->content_type.c_str());
                    out.set(http::field::cache_control, "public, max-age=86400, immutable");
                    return out;
                }
                return json_response(req, http::status::not_found,
                                     json{{"ok", false}, {"error", "not_found"}});
            }

            if (path == "/robots.txt")
                return text_response(req, http::status::ok, ctx.doorway->robots());

            if (auto pg = ctx.doorway->page(path, lang, host, secure)) {
                Response res{http::status::ok, req.version()};
                res.set("Content-Security-Policy", pg->csp);
                res.set("X-Robots-Tag", pg->robots);
                auto out = finish(std::move(res), req, std::move(pg->html),
                                  "text/html; charset=utf-8");
                // After finish(): common_headers stamps no-store, the page
                // policy decides for real.
                out.set(http::field::cache_control, pg->cache);
                if (!lang_cookie.empty()) {
                    out.set(http::field::set_cookie, lang_cookie);
                    // A language choice must not be cached as the page.
                    out.set(http::field::cache_control, "no-store");
                }
                return out;
            }

            // The live status page, in the site's own clothes.
            if (path == "/status")
                return doorway_html(ctx.doorway->render_status(lang), kCspDynamic);

            // Canonical short URLs: /R2R-XXXX-… (what QRs encode) and the
            // /i/<code> form older cards printed. Both land on the confirm
            // view; a hinted code that this relay has never seen is sent to
            // the relay its hint names.
            if (util::starts_with(path, "/R2R-") || util::starts_with(path, "/i/")) {
                const std::string raw =
                    util::starts_with(path, "/i/") ? path.substr(3) : path.substr(1);
                const std::string code = util::normalize_invite_code(raw);
                if (!code.empty()) {
                    if (!ctx.db.invite_info(code).found) {
                        const std::string hint = util::invite_hint_ip(code);
                        if (!hint.empty() && hint != our_ip())
                            return redirect("https://" + hint + "/redeem?code=" + code);
                    }
                    return redirect(base + "/redeem?code=" + code);
                }
            }

            // Contact-token page: /m/<token>.
            if (path == "/m" || util::starts_with(path, "/m/")) {
                const std::string token =
                    path == "/m" ? query_param(req.target(), "token") : path.substr(3);
                Doorway::ContactView cv;
                bool token_ok = token.size() >= 6 && token.size() <= 64;
                for (char c : token)
                    if (!std::isalnum(static_cast<unsigned char>(c))) token_ok = false;
                if (!token_ok) {
                    cv.err_text = ctx.doorway->text(lang, "m.err.malformed");
                } else {
                    const auto info = ctx.db.contact_info(token);
                    if (!info.found) cv.err_text = ctx.doorway->text(lang, "m.err.unknown");
                    else if (info.revoked) cv.err_text = ctx.doorway->text(lang, "m.err.revoked");
                    else if (!util::is_valid_fingerprint(info.fingerprint))
                        cv.err_text = ctx.doorway->text(lang, "m.err.no_contact");
                    else {
                        // Wallets add a contact from its R2R_ address (which carries the
                        // public key), not from the fingerprint, which is only a hash.
                        auto pub = util::b64_decode(info.pubkey_b64);
                        const std::string addr = pub ? crypto::contact_address(*pub) : std::string{};
                        if (addr.empty()) {
                            cv.err_text = ctx.doorway->text(lang, "m.err.no_contact");
                        } else {
                            cv.relay = ws_url();
                            cv.pubkey = "r2r:" + addr + "?relay=" + url_encode(cv.relay);
                        }
                    }
                }
                return doorway_html(ctx.doorway->render_contact(cv, lang, host), kCspDynamic);
            }

            // Setup-card metadata for the wallet and the forge.
            if (path == "/card") {
                const std::string code =
                    util::normalize_invite_code(query_param(req.target(), "code"));
                if (code.empty())
                    return json_response(req, http::status::bad_request,
                                         json{{"ok", false}, {"error", proto::kErrInviteInvalid}});
                const auto info = ctx.db.invite_info(code);
                const std::string redeem_url =
                    util::starts_with(code, "R2R-")
                        ? scheme + "://" + host + base + "/" + code
                        : scheme + "://" + host + base + "/redeem?code=" + code;
                json j{{"code", code}, {"redeem_url", redeem_url}, {"host", host}};
                j["contact_url"] = info.contact_token.empty()
                                       ? json()
                                       : json(scheme + "://" + host + base + "/m/" +
                                              info.contact_token);
                return json_response(req, http::status::ok, j);
            }

            if (path == "/api/stats") {
                const auto ds = ctx.db.stats();
                return json_response(req, http::status::ok,
                                     json{{"identities", ds.identities},
                                          {"invites_unused", ds.invites_unused},
                                          {"invites_claimed", ds.invites_burned}});
            }

            if (util::starts_with(path, "/api/contact/")) {
                const std::string token = path.substr(std::strlen("/api/contact/"));
                const auto info = ctx.db.contact_info(token);
                if (!info.found)
                    return json_response(req, http::status::not_found,
                                         json{{"ok", false}, {"error", "not_found"}});
                std::string address;
                if (auto pub = util::b64_decode(info.pubkey_b64); pub && !info.revoked)
                    address = crypto::contact_address(*pub);
                return json_response(req, http::status::ok,
                                     json{{"address", address},
                                          {"pubkey", info.revoked ? "" : info.fingerprint},
                                          {"ed25519", info.revoked ? "" : info.pubkey_b64},
                                          {"relay_url", info.revoked ? "" : ws_url()},
                                          {"revoked", info.revoked}});
            }
        }

        // Invite redemption: GET previews, POST consumes and mints the card.
        if (path == "/redeem" && (readable || method == http::verb::post)) {
            const bool is_post = method == http::verb::post;
            const std::string raw = is_post ? param_from(req.body(), "code")
                                            : query_param(req.target(), "code");
            Doorway::RedeemView v;
            v.view = "form";
            auto fail = [&](const char* key) {
                v.view = "err";
                v.err_text = ctx.doorway->text(lang, key);
            };

            if (!raw.empty()) {
                const std::string code = util::normalize_invite_code(raw);
                v.code = code.empty() ? util::trim(raw).substr(0, 40) : code;
                if (code.empty()) {
                    fail("redeem.err.malformed");
                } else {
                    const auto info = ctx.db.invite_info(code);
                    if (!info.found) {
                        const std::string hint = util::invite_hint_ip(code);
                        if (!hint.empty() && hint != our_ip())
                            return redirect("https://" + hint + "/redeem?code=" + code);
                        fail("redeem.err.unknown");
                    } else if (info.revoked) {
                        fail("redeem.err.revoked");
                    } else if (info.burned) {
                        fail("redeem.err.claimed");
                    } else if (info.locked) {
                        fail("redeem.err.inactive");
                        if (v.err_text == "redeem.err.inactive")
                            v.err_text = "This invite is not active yet. The person who shared it "
                                         "unlocks their invites by chatting on R2R first; try again later.";
                    } else if (!is_post) {
                        v.view = "confirm";
                    } else {
                        const auto card_key = crypto::random_bytes(32);
                        const std::string key_hex = util::hex_encode(card_key);
                        const std::string key_hash = util::hex_encode(
                            crypto::sha256(card_key.data(), card_key.size()));
                        switch (ctx.db.redeem_for_card(code, key_hash)) {
                            case Db::CardRedeemResult::ok:
                                v.view = "done";
                                v.card_str = "R2RSC1:" + key_hex + ":" + ws_url();
                                if (!info.contact_token.empty())
                                    v.contact_url = scheme + "://" + host + base + "/m/" +
                                                    info.contact_token;
                                break;
                            case Db::CardRedeemResult::race:
                                fail("redeem.err.race");
                                break;
                            default:
                                fail("redeem.err.mint_failed");
                                break;
                        }
                    }
                }
            }
            return doorway_html(ctx.doorway->render_redeem(v, lang, host), kCspDynamic);
        }
    }
#endif

    if (readable && path == "/") {
        return html_response(req, http::status::ok,
                             landing_page(ctx, ctx.hub.stats(), ctx.db.stats(), uptime));
    }

    if (readable && path == "/peers.json") {
        return json_response(req, http::status::ok, ctx.peers.to_public_json());
    }

    if (readable && path == "/node.json") {
        json j{{"node_id", ctx.node.node_id()},
               {"ed25519", ctx.node.ed_pub_b64()},
               {"x25519", ctx.node.x_pub_b64()},
               {"advertise", ctx.hub.self_address()},
               {"proto", proto::kVersion},
               {"version", R2R_VERSION},
               {"base", ctx.cfg.base_path},
               {"ws_port", ctx.cfg.ws_port},
               {"wss_port", ctx.cfg.tls_enabled ? ctx.cfg.wss_port : 0}};
        return json_response(req, http::status::ok, j);
    }

    if (readable && path == "/health") {
        return json_response(req, http::status::ok,
                             json{{"ok", true}, {"uptime", uptime}, {"tls", secure}});
    }

    if (readable && path == "/status.json") {
        const auto hs = ctx.hub.stats();
        const auto ds = ctx.db.stats();
        json j{{"node_id", ctx.node.node_id()},
               {"version", R2R_VERSION},
               {"base", ctx.cfg.base_path},
               {"uptime", uptime},
               {"peers_known", ctx.peers.size()},
               {"peers_active", ctx.peers.verified_count()},
               {"connections", hs.connections},
               {"clients", hs.clients},
               {"relay_links", hs.relay_links},
               {"tls_connections", hs.tls_connections},
               {"frames_in", hs.frames_in},
               {"frames_out", hs.frames_out},
               {"frames_forwarded", hs.forwarded},
               {"onion_peeled", hs.onion_peeled},
               {"drops_stored", ds.drops_stored},
               {"drop_bytes", ds.drop_bytes},
               {"drops_accepted", hs.drops_accepted},
               {"drops_rejected", hs.drops_rejected},
               {"identities", ds.identities},
               {"invites_open", ds.invites_unused},
               {"invites_burned", ds.invites_burned},
               {"invites_revoked", ds.invites_revoked},
               {"pools",
                json{{"common_used_bytes", ctx.db.free_tier_used_bytes()},
                     {"common_cap_bytes", ctx.cfg.pool_common_mb * 1024 * 1024},
                     {"market_cap_bytes", ctx.cfg.pool_market_mb * 1024 * 1024},
                     {"personal_cap_bytes", ctx.cfg.pool_personal_mb * 1024 * 1024}}},
               {"ttl_days", ctx.cfg.drop_ttl_days}};
        // The directory columns wallets shop by; cached copies of this page
        // only suggest -- the rent frame against the live relay is what
        // actually reserves. See docs/settlement-design.md.
        if (ctx.cfg.market_enabled()) {
            const std::int64_t pool = ctx.cfg.pool_market_mb * 1024 * 1024;
            const std::int64_t committed = ctx.db.rentals_committed_bytes();
            j["market"] = json{{"enabled", true},
                               {"price_gb_epoch_micro", ctx.cfg.market_price_micro},
                               {"epoch_days", ctx.cfg.rent_epoch_days},
                               {"pool_bytes", pool},
                               {"committed_bytes", committed},
                               {"available_bytes", pool > committed ? pool - committed : 0},
                               {"payout", ctx.cfg.payout_address},
                               {"vault", ctx.cfg.vault_address},
                               {"chain_id", ctx.cfg.chain_id}};
        }
        return json_response(req, http::status::ok, j);
    }

    if (readable && util::starts_with(path, "/invite/check/")) {
        const std::string code =
            util::normalize_invite_code(path.substr(std::strlen("/invite/check/")));
        if (code.empty())
            return json_response(req, http::status::bad_request,
                                 json{{"ok", false}, {"error", proto::kErrInviteInvalid}});
        const auto info = ctx.db.invite_info(code);
        const bool open = info.found && !info.burned && !info.revoked && !info.locked;
        return json_response(req, http::status::ok,
                             json{{"ok", true}, {"open", open}, {"locked", info.found && info.locked}});
    }

    if (method == http::verb::post && path == "/invite/claim") {
        json body = json::parse(req.body(), nullptr, false);
        if (body.is_discarded() || !body.is_object())
            return json_response(req, http::status::bad_request,
                                 json{{"ok", false}, {"error", proto::kErrBadFrame}});

        auto outcome = ctx.hub.claim_invite(body);
        if (!outcome.ok) {
            auto status = http::status::bad_request;
            if (outcome.error == proto::kErrInviteUsed ||
                outcome.error == proto::kErrAlreadyRegistered)
                status = http::status::conflict;
            else if (outcome.error == proto::kErrInviteLocked) status = http::status::forbidden;
            else if (outcome.error == proto::kErrInviteRevoked) status = http::status::gone;
            return json_response(req, status, json{{"ok", false}, {"error", outcome.error}});
        }
        json ok{{"ok", true},
                {"invites", outcome.invites},
                {"locked", outcome.locked},
                {"home_relay", ctx.hub.self_address()},
                {"node_id", ctx.node.node_id()}};
        if (!outcome.inviter.empty())
            ok["inviter"] = {{"id", outcome.inviter}, {"pubkey", outcome.inviter_pubkey}};
        return json_response(req, http::status::ok, ok);
    }

    if (method == http::verb::post && path == "/blob") return put_blob(req, ctx);
    if (readable && util::starts_with(path, "/blob/")) return get_blob(req, ctx, path);

    if (readable && path == "/ice") {
        // Handed to a client so it can open a direct peer connection. Media
        // never passes through the relay -- these only help the two ends find
        // each other through NAT.
        auto proof = header_auth(req, ctx);
        if (!proof) return unauthorised(req);
        return json_response(req, http::status::ok,
                             json{{"ok", true},
                                  {"iceServers", build_ice_servers(ctx.cfg, proof->fingerprint)},
                                  {"ttl", ctx.cfg.ice_ttl_seconds}});
    }

    if (readable && (path == "/assets" || util::starts_with(path, "/assets/")))
        return serve_asset(req, ctx, path);

    if (readable && path == "/robots.txt")
        return text_response(req, http::status::ok, "User-agent: *\nDisallow: /\n");

    if (!readable && method != http::verb::post) {
        Response res{http::status::method_not_allowed, req.version()};
        res.set(http::field::allow, "GET, HEAD, POST, OPTIONS");
        return finish(std::move(res), req, "method not allowed\n", "text/plain; charset=utf-8");
    }

    return json_response(req, http::status::not_found,
                         json{{"ok", false}, {"error", "not_found"}});
}

}  // namespace r2r
