// R2R relay -- the embedded doorway web site.
//
// Serves the operator-extracted template bundle (default <data-dir>/doorway):
// pre-rendered per-language pages with {{SENTINEL}} substitution, the shared
// stylesheet and scripts under nested asset paths, and the i18n catalogs the
// dynamic pages draw their strings from. The bundle is verified against its
// manifest.json at load; a partial or tampered bundle is refused loudly and
// the relay falls back to the built-in status page.
#pragma once

#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "config.hpp"

namespace r2r {

class Doorway {
public:
    // Reads and verifies the bundle. Returns false (and logs why) when the
    // directory is absent or fails verification; the relay then behaves as if
    // no doorway was installed.
    bool load(const Config& cfg);
    bool loaded() const { return loaded_; }

    struct Page {
        std::string html;        // sentinel-substituted, ready to send
        const char* csp;         // per-route Content-Security-Policy
        const char* robots;      // per-route X-Robots-Tag
        const char* cache;       // per-route Cache-Control
    };
    // Renders a static doorway page for a route ("/", "/privacy", ...) in the
    // visitor's language, falling back to English. Empty when the route is
    // not a doorway page.
    std::optional<Page> page(const std::string& route, const std::string& lang,
                             const std::string& host, bool https) const;

    struct Asset {
        std::string bytes;
        std::string content_type;
    };
    // A file under assets/ addressed by a nested relative path. Every path
    // component is validated; there is no way to traverse out of the bundle.
    std::optional<Asset> asset(const std::string& rel_path) const;

    // Language the visitor should get: "lang" cookie first, then the
    // Accept-Language header, then English.
    std::string pick_language(std::string_view cookie_header,
                              std::string_view accept_language) const;
    // Whether a catalog exists for this code (the ?lang= switcher validates
    // its input against this).
    bool has_language(const std::string& code) const { return catalogs_.count(code) > 0; }

    // The i18n catalog for a language (English when missing); used by the
    // server-rendered dynamic pages. Key lookup falls back to English.
    std::string text(const std::string& lang, const std::string& key) const;
    // Same, with {{NAME}} interpolation from `vars`. Keys ending in _html are
    // trusted markup from the catalog; everything else should be escaped by
    // the caller before it reaches a page.
    std::string text(const std::string& lang, const std::string& key,
                     const std::map<std::string, std::string>& vars) const;

    // --- server-rendered dynamic pages --------------------------------------
    struct RedeemView {
        std::string view;         // "form" | "confirm" | "done" | "err"
        std::string code;         // canonical code (echoed, escaped)
        std::string err_text;     // resolved error copy for "err"
        std::string card_str;     // R2RSC1 string for "done"
        std::string contact_url;  // optional second QR for "done"
    };
    std::string render_redeem(const RedeemView& v, const std::string& lang,
                              const std::string& host) const;

    struct ContactView {
        std::string err_text;  // non-empty -> error page
        std::string pubkey;    // contact link: r2r:R2R_…?relay=<url-encoded ws url>
        std::string relay;     // ws url to reach them
    };
    std::string render_contact(const ContactView& v, const std::string& lang,
                               const std::string& host) const;

    // The live status page: doorway-styled shell around a client-side view of
    // /status.json and /peers.json. Replaces the built-in landing page when
    // the doorway serves the site.
    std::string render_status(const std::string& lang) const;

    // robots.txt appropriate for a public doorway site, base-path aware.
    std::string robots() const;

    // The advertise address changed at runtime (admin_set_advertise): pages
    // render the new {{HOST}} from the next request on.
    void set_advertise_host(const std::string& host) {
        std::lock_guard<std::mutex> lock(host_mu_);
        advertise_host_ = host;
    }

private:
    struct Template {
        std::string body;   // raw bytes with sentinels still in place
    };

    std::string substitute(const std::string& body, const std::string& lang,
                           const std::string& host, bool https) const;

    // `active_route` ("/redeem") highlights that entry in the site nav.
    std::string shell(const std::string& lang, const std::string& title,
                      const std::string& extra_css, const std::string& body,
                      const std::string& active_route = std::string{}) const;

    std::string advertise_host() const {
        std::lock_guard<std::mutex> lock(host_mu_);
        return advertise_host_;
    }

    bool loaded_ = false;
    std::string mesh_svg_;
    std::string dir_;
    std::string base_path_;
    mutable std::mutex host_mu_;
    std::string advertise_host_;  // guarded by host_mu_
    std::string primary_, secondary_, bg_tint_;
    // route -> lang -> template ("index", "privacy", ...)
    std::map<std::string, std::map<std::string, Template>> pages_;
    // lang -> the site topbar (brand, nav, language switcher) lifted from
    // that language's index template, so dynamic pages match the site.
    std::map<std::string, std::string> headers_;
    // Short hash of manifest.json, appended to asset links (?v=…) so CDN and
    // browser caches roll over whenever the bundle changes.
    std::string asset_version_;
    std::map<std::string, nlohmann::json> catalogs_;   // lang -> key/value map
    std::map<std::string, std::string> lang_dir_;      // lang -> "ltr"/"rtl"
    std::vector<std::string> languages_;
};

}  // namespace r2r
