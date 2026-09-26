// R2R relay -- small dependency-free helpers.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace r2r::util {

using Bytes = std::vector<std::uint8_t>;

// ---- time ----------------------------------------------------------------
std::int64_t now_unix();
std::int64_t steady_ms();
std::string iso8601(std::int64_t unix_seconds);
std::string human_duration(std::int64_t seconds);

// ---- encodings -----------------------------------------------------------
std::string b64_encode(const void* data, std::size_t len);
inline std::string b64_encode(std::string_view s) { return b64_encode(s.data(), s.size()); }
inline std::string b64_encode(const Bytes& v) { return b64_encode(v.data(), v.size()); }
// Accepts standard and URL-safe alphabets, with or without padding.
std::optional<Bytes> b64_decode(std::string_view in);

std::string hex_encode(const void* data, std::size_t len);
inline std::string hex_encode(const Bytes& v) { return hex_encode(v.data(), v.size()); }
std::optional<Bytes> hex_decode(std::string_view in);

// ---- strings -------------------------------------------------------------
std::string trim(std::string_view s);
std::string to_lower(std::string_view s);
std::vector<std::string> split(std::string_view s, char delim, std::size_t max_parts = 0);
bool iequals(std::string_view a, std::string_view b);
bool starts_with(std::string_view s, std::string_view prefix);
std::string html_escape(std::string_view s);
// Constant-time comparison for secrets (invite codes, MACs).
bool secure_equals(std::string_view a, std::string_view b);

// ---- addresses -----------------------------------------------------------
struct Address {
    std::string host;          // bare host: "1.2.3.4", "relay.example", "::1"
    std::uint16_t port{0};
    bool ipv6_literal{false};

    std::string str() const;   // canonical "host:port" / "[v6]:port"
};

// Parses "host:port", "[v6]:port", or "host" (with default_port).
// Rejects schemes, paths, whitespace and control characters.
std::optional<Address> parse_address(std::string_view s, std::uint16_t default_port = 0);
std::string format_address(std::string_view host, std::uint16_t port);

bool is_valid_hostname(std::string_view h);
// True when `host` is an IP literal that is not globally routable: loopback,
// RFC 1918 / ULA private ranges, link-local, CGNAT, the unspecified address,
// multicast, documentation and reserved blocks. Hostnames return false; they
// are judged once resolved. This is what keeps a relay from being talked into
// dialling its own LAN.
bool is_non_public_ip(std::string_view host);
// Lowercase hex, 32-128 chars: a hash of a public key, never a name or an IP.
bool is_valid_fingerprint(std::string_view fp);
bool is_uuid_v4(std::string_view s);
// Canonicalises an invite code: legacy UUID v4 -> lowercase; the v2
// "R2R-XXXX-…" format -> uppercase with Crockford confusables folded.
// Returns the canonical form, or an empty string when the input is neither.
std::string normalize_invite_code(std::string_view s);
// "a.b.c.d" -> 8 uppercase hex characters for an invite routing hint;
// empty when the host is not a literal IPv4 address.
std::string ipv4_hint_hex(std::string_view host);
// The dotted IPv4 hidden in a hinted canonical invite code; empty when the
// code carries no hint.
std::string invite_hint_ip(std::string_view canonical_code);

// ---- filesystem ----------------------------------------------------------
bool file_exists(const std::string& path);

struct DirEntry {
    std::string name;
    std::int64_t size{0};
    std::int64_t mtime{0};
};
// Regular files only, sorted by name. Returns empty if `dir` is unreadable.
std::vector<DirEntry> list_files(const std::string& dir);
// Subdirectory names only, sorted. Used to walk the sharded blob tree.
std::vector<std::string> list_dirs(const std::string& dir);
// A single path component: no separators, no "..", no dotfiles, no control
// bytes. Anything a request could use to escape the asset directory is out.
bool is_safe_filename(std::string_view name);
bool make_dirs(const std::string& path, unsigned mode = 0700);
std::string dirname_of(const std::string& path);
std::string path_join(std::string_view a, std::string_view b);
std::optional<std::string> read_file(const std::string& path);
// Writes via a temp file + fsync + rename so readers never see a partial file.
bool write_file_atomic(const std::string& path, std::string_view data, unsigned mode = 0600);

// ---- rate limiting -------------------------------------------------------
// Classic token bucket. Not thread-safe; callers hold the session lock.
class TokenBucket {
public:
    TokenBucket() = default;
    TokenBucket(double rate_per_sec, double burst)
        : tokens_(burst), rate_(rate_per_sec), cap_(burst) {}

    bool consume(double n, std::int64_t now_ms);
    double tokens() const { return tokens_; }

private:
    double tokens_{0};
    double rate_{0};
    double cap_{0};
    std::int64_t last_ms_{0};
};

}  // namespace r2r::util
