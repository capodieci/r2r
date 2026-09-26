#include "doorway.hpp"

#include <cstdio>
#include <cstring>

#include "crypto.hpp"
#include "log.hpp"
#include "util.hpp"

using nlohmann::json;

namespace r2r {
namespace {

// The seven static pages of the doorway and where they live in the bundle.
const char* const kPageNames[] = {"index",      "privacy", "faq",      "network",
                                  "run-a-relay", "homes",   "downloads"};

// Routes the relay serves in code; a bundle template may not shadow them.
bool reserved_page_name(const std::string& n) {
    static const char* const kReserved[] = {
        "status", "redeem", "m",      "card",   "api",  "admin", "assets", "i",     "js",
        "health", "ice",    "blob",   "invite", "peers", "node", "robots", "index", "R2R"};
    for (const char* r : kReserved)
        if (n == r) return true;
    return false;
}

// An extra page name: lower-case letters, digits and dashes, so it can never
// collide with a short invite URL (/R2R-…) or a dotted endpoint.
bool extra_page_name_ok(const std::string& n) {
    if (n.empty() || n.size() > 40 || n.front() == '-' || n.back() == '-') return false;
    for (char c : n)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
    return !reserved_page_name(n);
}

struct Policy {
    const char* csp;
    const char* robots;
    const char* cache;
};

// Per-route policy from HANDOFF.md. 'unsafe-inline' scripts are required by
// the inline fetch loops and the card renderer bootstrap.
constexpr const char* kCspIndex =
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.youtube.com; "
    "frame-src https://www.youtube.com; img-src 'self' data:; style-src 'self' 'unsafe-inline'";
constexpr const char* kCspDocs =
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'";
constexpr const char* kCspLive =
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "connect-src 'self' https://*";

const Policy& policy_for(const std::string& page) {
    static const Policy index{kCspIndex, "index,follow", "public, max-age=300"};
    static const Policy docs{kCspDocs, "index,follow", "public, max-age=3600"};
    static const Policy live{kCspLive, "noindex,follow", "no-store"};
    if (page == "index") return index;
    if (page == "homes" || page == "downloads") return live;
    return docs;
}

// The bundle was pre-rendered on the PHP box, so its internal links still
// point at the .php routes and at the retired r2r.help account system. This
// rewrite is deterministic and runs once at load; registering is redeeming an
// invite here, and "log in" means opening the wallet from the downloads page.
std::string normalize_links(std::string s) {
    static const std::pair<const char*, const char*> kSubs[] = {
        {"href=\"/auth/login.php?intent=register\"", "href=\"{{BASE}}/redeem\""},
        {"href=\"/auth/login.php?intent=login\"", "href=\"{{BASE}}/downloads\""},
        {"href=\"/run-a-relay.php", "href=\"{{BASE}}/run-a-relay"},
        {"href=\"/privacy.php", "href=\"{{BASE}}/privacy"},
        {"href=\"/network.php", "href=\"{{BASE}}/network"},
        {"href=\"/faq.php", "href=\"{{BASE}}/faq"},
        {"href=\"/homes.php", "href=\"{{BASE}}/homes"},
        {"href=\"/downloads.php", "href=\"{{BASE}}/downloads"},
        {"href=\"/redeem.php", "href=\"{{BASE}}/redeem"},
        {"action=\"/redeem.php", "action=\"{{BASE}}/redeem"},
        {"href=\"/m.php", "href=\"{{BASE}}/m"},
        {"action=\"/m.php", "action=\"{{BASE}}/m"},
        {"href=\"/sippis-shell.css", "href=\"{{BASE}}/sippis-shell.css"},
        {"href=\"/favicon.svg\"", "href=\"{{BASE}}/favicon.svg\""},
        {"src=\"/sippis-logo.svg\"", "src=\"{{BASE}}/sippis-logo.svg\""},
        {"src=\"/js/", "src=\"{{BASE}}/js/"},
        {"href=\"/\"", "href=\"{{BASE}}/\""},
        // Prose and inline-JS mentions of the old routes.
        {"<code>/run-a-relay.php</code>", "<code>/run-a-relay</code>"},
        {"\\/run-a-relay.php", "\\/run-a-relay"},
    };
    for (const auto& [from, to] : kSubs) {
        const std::size_t flen = std::strlen(from);
        std::size_t pos = 0;
        while ((pos = s.find(from, pos)) != std::string::npos) {
            s.replace(pos, flen, to);
            pos += std::strlen(to);
        }
    }
    return s;
}

// #RRGGBB darkened towards black; used for the {{BG_TINT}} gradient stop.
std::string darken(const std::string& hex, double factor) {
    if (hex.size() != 7 || hex[0] != '#') return hex;
    auto chan = [&](int i) {
        const int v = std::stoi(hex.substr(static_cast<std::size_t>(i), 2), nullptr, 16);
        return static_cast<int>(v * factor);
    };
    char out[8];
    std::snprintf(out, sizeof out, "#%02X%02X%02X", chan(1), chan(3), chan(5));
    return out;
}

// Adds a "Status" entry to the site nav of a bundle page. The bundle predates
// the live status page, so the item is injected at load until a bundle rev
// ships it natively.
std::string inject_status_nav(std::string html) {
    const auto nav = html.find("class=\"site-nav\"");
    if (nav == std::string::npos) return html;
    const auto close = html.find("</nav>", nav);
    if (close == std::string::npos) return html;
    // A bundle that already links /status natively needs nothing.
    const auto have = html.find("/status\"", nav);
    if (have != std::string::npos && have < close) return html;
    html.insert(close,
                "      <a href=\"{{BASE}}/status\"\n"
                "         class=\"site-nav-item\"\n"
                "         >Status</a>\n  ");
    return html;
}

// Appends ?v=<version> to the bundle's own asset links so every bundle
// change is a new URL to CDN edges and browser caches. External links and
// page routes are left alone.
std::string version_assets(std::string html, const std::string& v) {
    if (v.empty()) return html;
    // A link may already carry a build-time ?v=… stamp (the old site tooling
    // baked timestamps in); ours must replace it, not stack behind it.
    auto stamp = [&](const std::string& name) {
        std::size_t p = 0;
        while ((p = html.find(name, p)) != std::string::npos) {
            const std::size_t e = p + name.size();
            if (e >= html.size()) break;
            if (html[e] == '?') {
                const auto close = html.find('"', e);
                if (close != std::string::npos) html.replace(e, close - e, "?v=" + v);
            } else if (html[e] == '"') {
                html.insert(e, "?v=" + v);
            }
            p = e;
        }
    };
    stamp("/sippis-shell.css");
    stamp("/favicon.svg");
    stamp("/favicon.ico");
    stamp("/sippis-logo.svg");
    std::size_t p = 0;
    while ((p = html.find("{{BASE}}/js/", p)) != std::string::npos) {
        const auto close = html.find('"', p);
        if (close == std::string::npos) break;
        const auto q = html.find('?', p);
        if (q != std::string::npos && q < close)
            html.replace(q, close - q, "?v=" + v);
        else if (html.compare(close - 3, 3, ".js") == 0)
            html.insert(close, "?v=" + v);
        p = close;
    }
    return html;
}

const char* content_type_of(const std::string& name) {
    auto ends = [&](std::string_view ext) {
        return name.size() > ext.size() &&
               util::iequals(name.substr(name.size() - ext.size()), ext);
    };
    if (ends(".css")) return "text/css; charset=utf-8";
    if (ends(".js") || ends(".mjs")) return "application/javascript; charset=utf-8";
    if (ends(".svg")) return "image/svg+xml";
    if (ends(".json")) return "application/json; charset=utf-8";
    if (ends(".png")) return "image/png";
    if (ends(".ico")) return "image/x-icon";
    if (ends(".woff2")) return "font/woff2";
    if (ends(".map")) return "application/json";
    return "application/octet-stream";
}

// A bundle-relative path is only ever joined component by component, each one
// vetted; there is no way to name a parent directory.
std::optional<std::string> safe_join(const std::string& root, const std::string& rel) {
    std::string full = root;
    std::string part;
    for (std::size_t i = 0; i <= rel.size(); ++i) {
        if (i == rel.size() || rel[i] == '/') {
            if (!util::is_safe_filename(part)) return std::nullopt;
            full = util::path_join(full, part);
            part.clear();
        } else {
            part += rel[i];
        }
    }
    return full;
}

}  // namespace

bool Doorway::load(const Config& cfg) {
    loaded_ = false;
    pages_.clear();
    catalogs_.clear();
    lang_dir_.clear();
    languages_.clear();

    dir_ = cfg.doorway_dir;
    base_path_ = cfg.base_path;
    primary_ = cfg.primary_color;
    secondary_ = cfg.secondary_color;
    bg_tint_ = darken(primary_, 0.70);
    if (!cfg.advertise.empty())
        if (auto a = util::parse_address(cfg.advertise, cfg.ws_port)) advertise_host_ = a->host;

    auto manifest_raw = util::read_file(util::path_join(dir_, "manifest.json"));
    if (!manifest_raw) {
        log::info("no doorway bundle at ", dir_, "; the built-in status page stays on /");
        return false;
    }
    // Any change to the bundle changes the manifest, so its hash versions
    // every asset URL: statics can be cached hard (immutable) yet update
    // instantly through a CDN when a new bundle lands.
    asset_version_ = util::hex_encode(crypto::sha256(*manifest_raw)).substr(0, 8);

    json manifest = json::parse(*manifest_raw, nullptr, false);
    if (manifest.is_discarded() || !manifest.contains("files") || !manifest["files"].is_object()) {
        log::error("doorway: ", dir_, "/manifest.json is not a valid bundle manifest");
        return false;
    }

    // Every file the manifest lists must be present and hash-identical --
    // except the i18n catalogs, which operators legitimately replace and
    // extend as fuller translations arrive. Extra unlisted files (new
    // languages, future pages) are fine too.
    for (const auto& [rel, info] : manifest["files"].items()) {
        const bool is_catalog = util::starts_with(rel, "i18n/");
        auto full = safe_join(dir_, rel);
        if (!full) {
            log::error("doorway: manifest names an unsafe path: ", rel);
            return false;
        }
        auto body = util::read_file(*full);
        if (!body) {
            if (is_catalog) {
                log::warn("doorway: catalog ", rel, " is missing; its language falls back "
                          "to English");
                continue;
            }
            log::error("doorway: bundle is incomplete, missing ", rel, "; refusing to serve it");
            return false;
        }
        const std::string want = info.value("sha256", std::string{});
        if (util::hex_encode(crypto::sha256(*body)) != want) {
            if (is_catalog) continue;  // an updated translation, not tampering
            log::error("doorway: ", rel, " does not match its manifest hash; refusing to serve "
                       "a tampered bundle");
            return false;
        }
    }

    // Languages and catalogs. languages.json names the set; any catalog the
    // operator has dropped alongside is picked up, missing ones fall back to
    // English at lookup time.
    if (auto raw = util::read_file(util::path_join(dir_, "i18n/languages.json"))) {
        json langs = json::parse(*raw, nullptr, false);
        if (!langs.is_discarded() && langs.contains("languages"))
            for (const auto& l : langs["languages"]) {
                const std::string code = l.value("code", std::string{});
                if (code.empty() || !util::is_safe_filename(code + ".json")) continue;
                languages_.push_back(code);
                lang_dir_[code] = l.value("dir", "ltr");
            }
    }
    if (languages_.empty()) languages_ = {"en"};

    for (const auto& code : languages_) {
        if (auto raw = util::read_file(util::path_join(dir_, "i18n/" + code + ".json"))) {
            json cat = json::parse(*raw, nullptr, false);
            if (!cat.is_discarded() && cat.is_object()) catalogs_[code] = std::move(cat);
        }
    }
    if (!catalogs_.count("en")) {
        log::error("doorway: i18n/en.json is required and missing or invalid");
        return false;
    }

    // Templates: English is required, other languages load when a future
    // bundle ships them pre-rendered.
    std::size_t loaded_pages = 0;
    for (const auto& code : languages_) {
        for (const char* page : kPageNames) {
            auto raw = util::read_file(
                util::path_join(dir_, "templates/" + code + "/" + page + ".html"));
            if (!raw) continue;
            pages_[page][code] = Template{version_assets(
                inject_status_nav(normalize_links(std::move(*raw))), asset_version_)};
            ++loaded_pages;
        }
    }
    // Any further templates/<lang>/<name>.html the bundle carries is served
    // at /<name> as well, with the docs policy, so a bundle revision can add
    // a page (the white paper, say) without a relay release. Names are
    // restricted and the relay's own routes cannot be shadowed.
    for (const auto& code : languages_) {
        for (const auto& e : util::list_files(util::path_join(dir_, "templates/" + code))) {
            static const std::string kExt = ".html";
            if (e.name.size() <= kExt.size() ||
                e.name.compare(e.name.size() - kExt.size(), kExt.size(), kExt) != 0)
                continue;
            const std::string name = e.name.substr(0, e.name.size() - kExt.size());
            if (pages_.count(name) && pages_[name].count(code)) continue;  // a core page
            if (!extra_page_name_ok(name)) {
                log::warn("doorway: ignoring template ", code, "/", e.name,
                          " (name is reserved or not [a-z0-9-])");
                continue;
            }
            auto raw = util::read_file(util::path_join(dir_, "templates/" + code + "/" + e.name));
            if (!raw) continue;
            pages_[name][code] = Template{version_assets(
                inject_status_nav(normalize_links(std::move(*raw))), asset_version_)};
            ++loaded_pages;
        }
    }
    bool complete = true;
    for (const char* page : kPageNames)
        if (!pages_.count(page) || !pages_[page].count("en")) complete = false;
    if (!complete) {
        log::error("doorway: the English template set is incomplete; refusing to serve it");
        return false;
    }

    // Lift the site topbar out of each language's index template so the
    // server-rendered pages (/redeem, /m) carry the same brand, nav and
    // language switcher as the rest of the site. Links are already
    // normalised; per-page "active"/"selected" marks are stripped here and
    // re-applied per request in shell().
    for (auto& [code, tpl] : pages_["index"]) {
        const auto start = tpl.body.find("<header class=\"topbar\">");
        const auto end = tpl.body.find("</header>");
        if (start == std::string::npos || end == std::string::npos || end <= start) continue;
        std::string hdr = tpl.body.substr(start, end - start + std::strlen("</header>"));
        auto strip = [&hdr](const std::string& from, const std::string& to) {
            std::size_t p = 0;
            while ((p = hdr.find(from, p)) != std::string::npos) {
                hdr.replace(p, from.size(), to);
                p += to.size();
            }
        };
        strip("site-nav-item active", "site-nav-item");
        strip("intent-pill active", "intent-pill");
        strip(" selected>", ">");
        headers_[code] = std::move(hdr);
    }

    // The animated mesh SVG partial; ships with a PHP comment header to strip.
    if (auto raw = util::read_file(util::path_join(dir_, "partials/mesh.php.inline"))) {
        const auto svg = raw->find("<svg");
        if (svg != std::string::npos) mesh_svg_ = raw->substr(svg);
    }

    log::info("doorway loaded: ", loaded_pages, " pages, ", catalogs_.size(),
              " language catalogs, serving from ", dir_);
    loaded_ = true;
    return true;
}

std::string Doorway::substitute(const std::string& body, const std::string& lang,
                                const std::string& host, bool https) const {
    // The host the visitor actually used wins: behind a proxying CDN the
    // advertise address is a bare origin IP for peers, not the site name.
    // The advertise host is only the fallback for hostless (debug) requests.
    const std::string adv = advertise_host();
    const std::string& use_host = host.empty() ? adv : host;
    std::string dir = "ltr";
    if (auto it = lang_dir_.find(lang); it != lang_dir_.end()) dir = it->second;

    std::string out;
    out.reserve(body.size() + 256);
    std::size_t i = 0;
    while (i < body.size()) {
        const std::size_t open = body.find("{{", i);
        if (open == std::string::npos) {
            out.append(body, i, std::string::npos);
            break;
        }
        out.append(body, i, open - i);
        const std::size_t close = body.find("}}", open);
        if (close == std::string::npos) {
            out.append(body, open, std::string::npos);
            break;
        }
        const std::string token = body.substr(open + 2, close - open - 2);
        if (token == "HOST") out += use_host;
        else if (token == "SCHEME") out += https ? "https" : "http";
        else if (token == "BASE") out += base_path_;
        else if (token == "LANG") out += lang;
        else if (token == "LANG_DIR") out += dir;
        else if (token == "PRIMARY") out += primary_;
        else if (token == "SECONDARY") out += secondary_;
        else if (token == "BG_TINT") out += bg_tint_;
        else {
            // Not ours ({{ERR}}, {{FILE}}, … belong to the page's own JS);
            // pass it through untouched.
            out.append(body, open, close - open + 2);
        }
        i = close + 2;
    }
    return out;
}

std::optional<Doorway::Page> Doorway::page(const std::string& route, const std::string& lang,
                                           const std::string& host, bool https) const {
    if (!loaded_) return std::nullopt;
    std::string name;
    if (route == "/" || route == "/index.html") name = "index";
    else if (route.size() > 1 && route[0] == '/') name = route.substr(1);
    if (name.find('/') != std::string::npos) return std::nullopt;
    auto pit = pages_.find(name);
    if (pit == pages_.end()) return std::nullopt;

    auto lit = pit->second.find(lang);
    std::string used_lang = lang;
    if (lit == pit->second.end()) {
        lit = pit->second.find("en");
        used_lang = "en";
        if (lit == pit->second.end()) return std::nullopt;
    }
    const Policy& pol = policy_for(name);
    return Page{substitute(lit->second.body, used_lang, host, https), pol.csp, pol.robots,
                pol.cache};
}

std::optional<Doorway::Asset> Doorway::asset(const std::string& rel_path) const {
    if (!loaded_ || rel_path.empty()) return std::nullopt;
    auto full = safe_join(util::path_join(dir_, "assets"), rel_path);
    if (!full) return std::nullopt;
    auto body = util::read_file(*full);
    if (!body || body->size() > 16u * 1024 * 1024) return std::nullopt;
    return Asset{std::move(*body), content_type_of(rel_path)};
}

std::string Doorway::pick_language(std::string_view cookie_header,
                                   std::string_view accept_language) const {
    // Cookie "lang=xx" wins; it is how the language switcher persists a choice.
    const std::string cookies(cookie_header);
    std::size_t pos = 0;
    while ((pos = cookies.find("lang=", pos)) != std::string::npos) {
        // Must start a cookie, not be the tail of another name.
        if (pos == 0 || cookies[pos - 1] == ' ' || cookies[pos - 1] == ';') {
            std::size_t end = cookies.find(';', pos);
            std::string val = cookies.substr(pos + 5, end == std::string::npos
                                                          ? std::string::npos
                                                          : end - pos - 5);
            val = util::to_lower(util::trim(val));
            if (catalogs_.count(val)) return val;
        }
        pos += 5;
    }

    // Accept-Language, primary subtags in order.
    std::string token;
    const std::string accept(accept_language);
    for (std::size_t i = 0; i <= accept.size(); ++i) {
        if (i == accept.size() || accept[i] == ',') {
            std::string t = util::to_lower(util::trim(token));
            token.clear();
            const auto semi = t.find(';');
            if (semi != std::string::npos) t = t.substr(0, semi);
            const auto dash = t.find('-');
            if (dash != std::string::npos) t = t.substr(0, dash);
            if (!t.empty() && catalogs_.count(t)) return t;
        } else {
            token += accept[i];
        }
    }
    return "en";
}

std::string Doorway::text(const std::string& lang, const std::string& key) const {
    auto lookup = [&](const std::string& code) -> std::optional<std::string> {
        auto it = catalogs_.find(code);
        if (it == catalogs_.end()) return std::nullopt;
        auto v = it->second.find(key);
        if (v == it->second.end() || !v->is_string()) return std::nullopt;
        return v->get<std::string>();
    };
    if (auto s = lookup(lang)) return *s;
    if (auto s = lookup("en")) return *s;
    return key;
}

std::string Doorway::text(const std::string& lang, const std::string& key,
                          const std::map<std::string, std::string>& vars) const {
    std::string s = text(lang, key);
    for (const auto& [name, value] : vars) {
        const std::string token = "{{" + name + "}}";
        std::size_t pos = 0;
        while ((pos = s.find(token, pos)) != std::string::npos) {
            s.replace(pos, token.size(), value);
            pos += value.size();
        }
    }
    return s;
}

// ------------------------------------------------- dynamic page rendering --

std::string Doorway::shell(const std::string& lang, const std::string& title,
                           const std::string& extra_css, const std::string& body,
                           const std::string& active_route) const {
    std::string dir = "ltr";
    if (auto it = lang_dir_.find(lang); it != lang_dir_.end()) dir = it->second;
    const std::string& b = base_path_;

    std::string html;
    html.reserve(body.size() + 2048);
    html += "<!DOCTYPE html>\n<html lang=\"" + util::html_escape(lang) + "\" dir=\"" + dir +
            "\">\n<head>\n<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
            "<meta name=\"robots\" content=\"noindex,nofollow\">\n"
            "<title>" + util::html_escape(title) + "</title>\n"
            "<link rel=\"icon\" type=\"image/svg+xml\" href=\"" + b + "/favicon.svg?v=" +
            asset_version_ + "\">\n"
            "<link rel=\"stylesheet\" href=\"" + b + "/sippis-shell.css?v=" + asset_version_ +
            "\">\n"
            "<style>\n:root { --primary: " + primary_ + "; --secondary: " + secondary_ +
            "; --bg-tint: " + bg_tint_ + "; }\n" + extra_css + "</style>\n</head>\n<body>\n";

    auto hit = headers_.find(lang);
    if (hit == headers_.end()) hit = headers_.find("en");
    if (hit != headers_.end()) {
        // The real site topbar, lifted from the index template at load time.
        std::string hdr = hit->second;
        std::size_t p = 0;
        while ((p = hdr.find("{{BASE}}", p)) != std::string::npos) {
            hdr.replace(p, 8, b);
            p += b.size();
        }
        const std::string opt = "value=\"" + lang + "\"";
        if (auto o = hdr.find(opt); o != std::string::npos)
            hdr.insert(o + opt.size(), " selected");
        if (!active_route.empty()) {
            const std::string href = "href=\"" + b + active_route + "\"";
            if (auto a = hdr.find(href); a != std::string::npos)
                if (auto c = hdr.find("site-nav-item", a); c != std::string::npos)
                    hdr.insert(c + std::strlen("site-nav-item"), " active");
        }
        html += hdr + "\n";
    } else {
        html += "<header class=\"topbar\"><a class=\"brand\" href=\"" + b +
                "/\"><strong>R2\xD0\xAF</strong></a>"
                "<div class=\"topbar-actions\"><a class=\"pill\" href=\"" + b + "/redeem\">" +
                util::html_escape(text(lang, "topbar.register")) + "</a></div></header>\n";
    }
    html += body;
    html += "\n<footer>" + util::html_escape(text(lang, "topbar.powered_by")) +
            "</footer>\n</body>\n</html>\n";
    return html;
}

std::string Doorway::render_redeem(const RedeemView& v, const std::string& lang,
                                   const std::string& host) const {
    const std::string& b = base_path_;
    auto h = [](const std::string& s) { return util::html_escape(s); };
    auto t = [&](const char* key) { return text(lang, key); };
    const std::map<std::string, std::string> hostvar{{"HOST", h(host)}};

    static const char* kCss =
        ".r2r-mesh-frame { max-width:100%; margin:0 auto; text-align:center; }\n"
        ".r2r-mesh-frame svg { display:block; margin:0 auto; width:100%; max-width:460px; height:auto; }\n"
        ".redeem-form { width:310px; max-width:100%; margin:24px auto; text-align:center; }\n"
        ".redeem-form input[type=text] { width:100%; box-sizing:border-box; padding:14px 16px;"
        " font-size:20px; letter-spacing:2px; text-align:center; text-transform:uppercase;"
        " border:2px solid var(--primary); border-radius:8px; background:transparent;"
        " color:inherit; font-family:monospace; }\n"
        ".redeem-form button, .redeem-form .cta { margin-top:16px; padding:12px 28px;"
        " font-size:18px; background:var(--primary); color:#fff; border:0; border-radius:8px;"
        " cursor:pointer; text-decoration:none; display:inline-block; }\n"
        ".confirm-code { display:inline-block; padding:14px 24px; font-family:monospace;"
        " font-size:26px; letter-spacing:2px; background:rgba(0,0,0,0.35);"
        " border:1px solid var(--primary); border-radius:8px; margin:12px 0; }\n"
        ".card-box { max-width:640px; margin:24px auto; padding:20px; text-align:center;"
        " background:rgba(0,0,0,0.15); border-radius:12px; }\n"
        "#card-canvas { display:block; width:100%; max-width:360px; height:auto; margin:0 auto;"
        " border-radius:12px; box-shadow:0 8px 24px rgba(0,0,0,0.35); }\n"
        ".card-download { margin-top:12px; padding:10px 20px; background:var(--primary);"
        " color:#fff; border:0; border-radius:8px; cursor:pointer; font-size:14px; }\n"
        ".card-str { display:block; word-break:break-all; font-family:monospace; font-size:13px;"
        " background:rgba(0,0,0,0.35); padding:12px; border-radius:6px; margin-top:12px;"
        " user-select:all; }\n"
        ".warn { color:#ff9; margin:12px 0; }\n"
        ".err { color:#f88; margin:24px auto; max-width:480px; text-align:center; font-size:18px; }\n"
        ".steps { max-width:640px; margin:24px auto; text-align:left; }\n"
        ".steps li { margin:8px 0; }\n"
        ".cancel-link { display:block; margin-top:12px; color:rgba(255,255,255,0.6); font-size:14px; }\n";

    std::string body = "<main class=\"hero\">\n<div class=\"r2r-mesh-frame\">" + mesh_svg_ +
                       "</div>\n";

    if (v.view == "done") {
        json opts{{"code", v.code},
                  {"redeemUrl", v.card_str},
                  {"contactUrl", v.contact_url.empty() ? json() : json(v.contact_url)},
                  {"host", host},
                  {"primaryColor", primary_}};
        body += "<h1>" + h(t("redeem.done.h1")) + "</h1>\n<p class=\"tagline\">" +
                h(t("redeem.done.tagline")) + "</p>\n<div class=\"card-box\">\n"
                "<canvas id=\"card-canvas\" aria-label=\"Setup card\"></canvas>\n"
                "<button type=\"button\" class=\"card-download\" "
                "onclick=\"R2R.downloadCardPNG(document.getElementById('card-canvas'),"
                "'r2r-setup-card.png')\">Download card PNG</button>\n"
                "<code class=\"card-str\">" + h(v.card_str) + "</code>\n"
                "<p class=\"warn\">" + h(t("redeem.done.warn")) + "</p>\n</div>\n"
                "<ol class=\"steps\">\n<li>" + h(t("redeem.done.step1")) + "</li>\n<li>" +
                h(t("redeem.done.step2")) + "</li>\n<li>" + text(lang, "redeem.done.step3_html") +
                "</li>\n<li>" + text(lang, "redeem.done.step4_html", hostvar) + "</li>\n</ol>\n"
                "<script src=\"" + b + "/js/qrcode.min.js\"></script>\n"
                "<script src=\"" + b + "/js/card.js\"></script>\n"
                "<script>R2R.renderCard(document.getElementById('card-canvas'), " +
                opts.dump() + ");</script>\n";
    } else if (v.view == "confirm") {
        body += "<h1>" + h(t("redeem.confirm.h1")) + "</h1>\n<p class=\"tagline\">" +
                text(lang, "redeem.confirm.tagline_html") + "</p>\n"
                "<div class=\"confirm-code\">" + h(v.code) + "</div>\n"
                "<form class=\"redeem-form\" method=\"post\" action=\"" + b + "/redeem\">\n"
                "<input type=\"hidden\" name=\"code\" value=\"" + h(v.code) + "\">\n"
                "<br><button type=\"submit\">" + h(t("redeem.confirm.button")) + "</button>\n"
                "<a class=\"cancel-link\" href=\"" + b + "/\">" +
                text(lang, "redeem.confirm.cancel_html", hostvar) + "</a>\n</form>\n"
                "<p class=\"steps\" style=\"text-align:center\">" +
                text(lang, "redeem.confirm.accidental_html") + "</p>\n";
    } else if (v.view == "err") {
        body += "<h1>" + h(t("redeem.err_view.h1")) + "</h1>\n<p class=\"err\">" +
                h(v.err_text) + "</p>\n"
                "<form class=\"redeem-form\" method=\"get\" action=\"" + b + "/redeem\">\n"
                "<input type=\"text\" name=\"code\" value=\"" + h(v.code) +
                "\" placeholder=\"" + h(t("redeem.form.placeholder")) +
                "\" autocomplete=\"off\" autofocus>\n<br><button type=\"submit\">" +
                h(t("redeem.err_view.try_again")) + "</button>\n</form>\n";
    } else {
        body += "<h1>" + h(t("redeem.form.h1")) + "</h1>\n<p class=\"tagline\">" +
                h(t("redeem.form.tagline")) + "</p>\n"
                "<form class=\"redeem-form\" method=\"get\" action=\"" + b + "/redeem\">\n"
                "<input type=\"text\" name=\"code\" placeholder=\"" +
                h(t("redeem.form.placeholder")) +
                "\" autocomplete=\"off\" autofocus>\n<br><button type=\"submit\">" +
                h(t("redeem.form.button")) + "</button>\n</form>\n"
                "<p class=\"steps\">" + text(lang, "redeem.form.no_code_html") + "</p>\n";
    }
    body += "</main>";

    return shell(lang, text(lang, "redeem.meta.title", hostvar), kCss, body, "/redeem");
}

std::string Doorway::render_contact(const ContactView& v, const std::string& lang,
                                    const std::string& host) const {
    const std::string& b = base_path_;
    auto h = [](const std::string& s) { return util::html_escape(s); };
    auto t = [&](const char* key) { return text(lang, key); };
    const std::map<std::string, std::string> hostvar{{"HOST", h(host)}};

    static const char* kCss =
        ".contact-box { max-width:620px; margin:24px auto; padding:20px; text-align:center;"
        " background:rgba(0,0,0,0.15); border-radius:12px; }\n"
        ".fld { text-align:left; margin:14px 0; }\n"
        ".fld label { display:block; font-size:12px; color:rgba(255,255,255,0.55);"
        " margin-bottom:4px; text-transform:uppercase; letter-spacing:1px; }\n"
        ".fld code { display:block; word-break:break-all; font-family:monospace; font-size:13px;"
        " background:rgba(0,0,0,0.35); padding:10px; border-radius:6px; user-select:all; }\n"
        ".cp { padding:10px 18px; background:var(--primary); color:#fff; border:0;"
        " border-radius:6px; cursor:pointer; font-size:14px; margin-top:6px; }\n"
        ".err { color:#f88; text-align:center; font-size:18px; margin:32px auto; max-width:480px; }\n"
        "ol.steps { max-width:620px; margin:20px auto; text-align:left; }\n"
        "ol.steps li { margin:8px 0; }\n";

    std::string body = "<main class=\"hero\">\n<img class=\"logo\" src=\"" + b +
                       "/sippis-logo.svg\" alt=\"R2R\">\n";
    if (!v.err_text.empty()) {
        body += "<h1>" + h(t("m.err.h1")) + "</h1>\n<p class=\"err\">" + h(v.err_text) +
                "</p>\n<a class=\"cta\" href=\"" + b + "/\">" +
                text(lang, "m.err.back_html", hostvar) + "</a>\n";
    } else {
        const std::string copied = h(t("m.ok.copied"));
        body += "<h1>" + h(t("m.ok.h1")) + "</h1>\n<p class=\"tagline\">" + h(t("m.ok.tagline")) +
                "</p>\n<div class=\"contact-box\">\n"
                "<div class=\"fld\"><label>" + h(t("m.ok.pubkey_label")) + "</label>"
                "<code id=\"pubkey\">" + h(v.pubkey) + "</code>"
                "<button class=\"cp\" onclick=\"navigator.clipboard.writeText("
                "document.getElementById('pubkey').textContent);this.textContent='" + copied +
                "'\">" + h(t("m.ok.copy_pubkey")) + "</button></div>\n"
                "<div class=\"fld\"><label>" + h(t("m.ok.relay_label")) + "</label>"
                "<code id=\"relay\">" + h(v.relay) + "</code>"
                "<button class=\"cp\" onclick=\"navigator.clipboard.writeText("
                "document.getElementById('relay').textContent);this.textContent='" + copied +
                "'\">" + h(t("m.ok.copy_relay")) + "</button></div>\n</div>\n"
                "<ol class=\"steps\">\n<li>" + h(t("m.ok.step1")) + "</li>\n<li>" +
                text(lang, "m.ok.step2_html") + "</li>\n<li>" + h(t("m.ok.step3")) +
                "</li>\n<li>" + h(t("m.ok.step4")) + "</li>\n</ol>\n"
                "<p style=\"text-align:center;font-size:14px;color:rgba(255,255,255,0.5);"
                "margin-top:24px\">" + text(lang, "m.ok.no_wallet_html") + "</p>\n";
    }
    body += "</main>";
    return shell(lang, text(lang, "m.meta.title", hostvar), kCss, body);
}

std::string Doorway::render_status(const std::string& lang) const {
    const std::string& b = base_path_;

    static const char* kCss =
        ".status-wrap { max-width: 900px; margin: 24px auto 60px; text-align: left; padding: 0 16px; }\n"
        ".status-wrap h1 { text-align: center; font-size: clamp(26px,4vw,36px); margin: 0 0 4px; }\n"
        ".status-wrap .sub { text-align: center; color: rgba(255,255,255,0.6); margin: 0 0 24px; font-size: 14px; }\n"
        ".stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px,1fr)); gap: 12px; margin: 18px 0; }\n"
        ".stat { background: rgba(0,0,0,0.20); border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 14px 16px; }\n"
        ".stat b { display: block; font-size: 22px; font-variant-numeric: tabular-nums; }\n"
        ".stat span { color: rgba(255,255,255,0.6); font-size: 12.5px; text-transform: uppercase; letter-spacing: 0.06em; }\n"
        ".status-wrap h2 { color: var(--primary); font-size: 17px; margin: 26px 0 10px; }\n"
        ".kv { width: 100%; border-collapse: collapse; font-size: 14px; }\n"
        ".kv td { padding: 6px 8px; border-top: 1px solid rgba(255,255,255,0.08); }\n"
        ".kv td:first-child { color: rgba(255,255,255,0.6); width: 38%; }\n"
        ".kv code { font-family: ui-monospace,Menlo,monospace; font-size: 13px; overflow-wrap: anywhere; }\n"
        ".pill-ok { color: #79d0a3; } .pill-bad { color: #f88; }\n"
        ".ep { display: inline-block; margin: 4px 8px 4px 0; padding: 6px 12px; border: 1px solid rgba(255,255,255,0.15);"
        " border-radius: 8px; color: var(--primary); text-decoration: none; font-family: ui-monospace,Menlo,monospace; font-size: 13px; }\n"
        ".ep:hover { border-color: var(--primary); }\n"
        ".muted { color: rgba(255,255,255,0.55); font-size: 13px; }\n";

    std::string body =
        "<div class=\"status-wrap\">\n"
        "<h1>Relay status</h1>\n"
        "<p class=\"sub\" id=\"st-sub\">loading&hellip;</p>\n"
        "<div class=\"stat-grid\" id=\"st-grid\"></div>\n"
        "<h2>This node</h2>\n<table class=\"kv\" id=\"st-node\"></table>\n"
        "<h2>Network</h2>\n<table class=\"kv\" id=\"st-peers\"></table>\n"
        "<h2>Endpoints</h2>\n<p>\n";
    for (const char* ep : {"/status.json", "/peers.json", "/node.json", "/health"})
        body += "<a class=\"ep\" target=\"_blank\" rel=\"noopener\" href=\"" + b + ep + "\">" +
                ep + "</a>\n";
    body +=
        "</p>\n<p class=\"muted\">Numbers refresh every 10 seconds. This page shows only what the "
        "relay publishes anyway &mdash; no client data, no addresses, no logs.</p>\n"
        "</div>\n"
        "<script>\n"
        "(function () {\n"
        "  'use strict';\n"
        "  var B = '" + b + "';\n"
        "  function el(id) { return document.getElementById(id); }\n"
        "  function esc(s) { return String(s).replace(/[&<>\"]/g, function (c) {"
        " return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;' }[c]; }); }\n"
        "  function fmtBytes(n) { n = n || 0; if (n >= 1073741824) return (n / 1073741824).toFixed(1) + ' GB';"
        " if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';"
        " if (n >= 1024) return (n / 1024).toFixed(0) + ' KB'; return n + ' B'; }\n"
        "  function fmtUp(s) { s = s | 0; var d = (s / 86400) | 0, h = ((s % 86400) / 3600) | 0, m = ((s % 3600) / 60) | 0;\n"
        "    return (d ? d + 'd ' : '') + h + 'h ' + m + 'm'; }\n"
        "  function stat(label, value) { return '<div class=stat><b>' + value + '</b><span>' + label + '</span></div>'; }\n"
        "  function row(k, v) { return '<tr><td>' + k + '</td><td>' + v + '</td></tr>'; }\n"
        "  function refresh() {\n"
        "    fetch(B + '/status.json').then(function (r) { return r.json(); }).then(function (j) {\n"
        "      el('st-sub').textContent = 'r2r-relay ' + j.version + ' \\u00b7 up ' + fmtUp(j.uptime);\n"
        "      var g = '';\n"
        "      g += stat('active peers', j.peers_active | 0);\n"
        "      g += stat('known relays', j.peers_known | 0);\n"
        "      g += stat('connections', j.connections | 0);\n"
        "      g += stat('identities', j.identities | 0);\n"
        "      g += stat('messages held', j.drops_stored | 0);\n"
        "      g += stat('stored bytes', fmtBytes(j.drop_bytes));\n"
        "      g += stat('frames relayed', j.frames_forwarded | 0);\n"
        "      g += stat('onion peeled', j.onion_peeled | 0);\n"
        "      el('st-grid').innerHTML = g;\n"
        "      var n = '';\n"
        "      n += row('node id', '<code>' + esc(j.node_id || '') + '</code>');\n"
        "      n += row('invites', (j.invites_open | 0) + ' open \\u00b7 ' + (j.invites_burned | 0) + ' used"
        " \\u00b7 ' + (j.invites_revoked | 0) + ' revoked');\n"
        "      n += row('message retention', (j.ttl_days | 0) + ' days');\n"
        "      if (j.pools && j.pools.common_cap_bytes) n += row('common pool', fmtBytes(j.pools.common_used_bytes)"
        " + ' of ' + fmtBytes(j.pools.common_cap_bytes));\n"
        "      if (j.market && j.market.enabled) n += row('storage market', fmtBytes(j.market.available_bytes)"
        " + ' free of ' + fmtBytes(j.market.pool_bytes) + ' \\u00b7 $' + (j.market.price_gb_epoch_micro / 1e6).toFixed(2)"
        " + ' / GB\\u00b7month');\n"
        "      el('st-node').innerHTML = n;\n"
        "    }).catch(function () { el('st-sub').textContent = 'status.json unreachable'; });\n"
        "    fetch(B + '/peers.json').then(function (r) { return r.json(); }).then(function (j) {\n"
        "      var rows = '';\n"
        "      (j.peers || []).forEach(function (p) {\n"
        "        rows += row('<code>' + esc(p.address || '') + '</code>',\n"
        "          p.verified ? '<span class=pill-ok>verified</span>' : '<span class=muted>seen</span>');\n"
        "      });\n"
        "      el('st-peers').innerHTML = rows || row('<span class=muted>no peers yet</span>', '');\n"
        "    }).catch(function () {});\n"
        "  }\n"
        "  refresh();\n"
        "  setInterval(refresh, 10000);\n"
        "})();\n"
        "</script>\n";

    return shell(lang, "Relay status", kCss, body, "/status");
}

std::string Doorway::robots() const {
    const std::string& b = base_path_;
    return "User-agent: *\n"
           "Allow: " + (b.empty() ? "/" : b) + "\n"
           "Disallow: " + b + "/redeem\n"
           "Disallow: " + b + "/m/\n"
           "Disallow: " + b + "/admin\n";
}

}  // namespace r2r
