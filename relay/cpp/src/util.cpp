#include "util.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace r2r::util {
namespace {

constexpr char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::array<signed char, 256> make_b64_reverse() {
    std::array<signed char, 256> t{};
    t.fill(-1);
    for (int i = 0; i < 64; ++i) t[static_cast<unsigned char>(kB64[i])] = static_cast<signed char>(i);
    t[static_cast<unsigned char>('-')] = 62;  // URL-safe alphabet
    t[static_cast<unsigned char>('_')] = 63;
    return t;
}

const std::array<signed char, 256> kB64Rev = make_b64_reverse();

bool parse_port(std::string_view s, std::uint16_t& out) {
    if (s.empty() || s.size() > 5) return false;
    unsigned v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        v = v * 10 + static_cast<unsigned>(c - '0');
    }
    if (v == 0 || v > 65535) return false;
    out = static_cast<std::uint16_t>(v);
    return true;
}

}  // namespace

// ---------------------------------------------------------------- time -----

std::int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t steady_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::string iso8601(std::int64_t unix_seconds) {
    std::time_t t = static_cast<std::time_t>(unix_seconds);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

std::string human_duration(std::int64_t seconds) {
    if (seconds < 0) seconds = 0;
    const std::int64_t d = seconds / 86400;
    const std::int64_t h = (seconds % 86400) / 3600;
    const std::int64_t m = (seconds % 3600) / 60;
    const std::int64_t s = seconds % 60;
    std::string out;
    char buf[32];
    if (d) { std::snprintf(buf, sizeof buf, "%lldd ", static_cast<long long>(d)); out += buf; }
    if (d || h) { std::snprintf(buf, sizeof buf, "%lldh ", static_cast<long long>(h)); out += buf; }
    if (d || h || m) { std::snprintf(buf, sizeof buf, "%lldm ", static_cast<long long>(m)); out += buf; }
    std::snprintf(buf, sizeof buf, "%llds", static_cast<long long>(s));
    out += buf;
    return out;
}

// ----------------------------------------------------------- encodings -----

std::string b64_encode(const void* data, std::size_t len) {
    const auto* p = static_cast<const unsigned char*>(data);
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        const std::uint32_t v = (std::uint32_t(p[i]) << 16) | (std::uint32_t(p[i + 1]) << 8) | p[i + 2];
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.push_back(kB64[(v >> 6) & 63]);
        out.push_back(kB64[v & 63]);
    }
    const std::size_t rem = len - i;
    if (rem == 1) {
        const std::uint32_t v = std::uint32_t(p[i]) << 16;
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.append("==");
    } else if (rem == 2) {
        const std::uint32_t v = (std::uint32_t(p[i]) << 16) | (std::uint32_t(p[i + 1]) << 8);
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.push_back(kB64[(v >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

std::optional<Bytes> b64_decode(std::string_view in) {
    Bytes out;
    out.reserve((in.size() / 4) * 3 + 3);
    std::uint32_t acc = 0;
    int nbits = 0;
    std::size_t pad = 0;
    for (char ch : in) {
        const auto c = static_cast<unsigned char>(ch);
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (c == '=') { ++pad; continue; }
        if (pad) return std::nullopt;  // data after padding
        const signed char d = kB64Rev[c];
        if (d < 0) return std::nullopt;
        acc = (acc << 6) | static_cast<std::uint32_t>(d);
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            out.push_back(static_cast<std::uint8_t>((acc >> nbits) & 0xff));
        }
    }
    if (pad > 2) return std::nullopt;
    // Leftover bits must be zero padding, never data.
    if (nbits >= 6) return std::nullopt;
    if (nbits && ((acc & ((1u << nbits) - 1)) != 0)) return std::nullopt;
    return out;
}

std::string hex_encode(const void* data, std::size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    const auto* p = static_cast<const unsigned char*>(data);
    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out[2 * i] = kHex[p[i] >> 4];
        out[2 * i + 1] = kHex[p[i] & 0x0f];
    }
    return out;
}

std::optional<Bytes> hex_decode(std::string_view in) {
    if (in.size() % 2 != 0) return std::nullopt;
    Bytes out;
    out.reserve(in.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < in.size(); i += 2) {
        const int hi = nib(in[i]);
        const int lo = nib(in[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

// ------------------------------------------------------------- strings -----

std::string trim(std::string_view s) {
    auto is_sp = [](unsigned char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    std::size_t b = 0, e = s.size();
    while (b < e && is_sp(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && is_sp(static_cast<unsigned char>(s[e - 1]))) --e;
    return std::string(s.substr(b, e - b));
}

std::string to_lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

std::vector<std::string> split(std::string_view s, char delim, std::size_t max_parts) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (true) {
        if (max_parts && out.size() + 1 == max_parts) {
            out.emplace_back(s.substr(start));
            break;
        }
        const auto pos = s.find(delim, start);
        if (pos == std::string_view::npos) {
            out.emplace_back(s.substr(start));
            break;
        }
        out.emplace_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

std::string html_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(c);
        }
    }
    return out;
}

bool secure_equals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return diff == 0;
}

// ----------------------------------------------------------- addresses -----

std::string Address::str() const { return format_address(host, port); }

std::string format_address(std::string_view host, std::uint16_t port) {
    std::string out;
    const bool v6 = host.find(':') != std::string_view::npos;
    if (v6) { out += '['; out += host; out += ']'; }
    else out += host;
    out += ':';
    out += std::to_string(port);
    return out;
}

bool is_valid_hostname(std::string_view h) {
    if (h.empty() || h.size() > 253) return false;
    if (h.front() == '.' || h.back() == '.' || h.front() == '-') return false;
    if (h.find("..") != std::string_view::npos) return false;
    bool has_alnum = false;
    for (char ch : h) {
        const auto c = static_cast<unsigned char>(ch);
        if (std::isalnum(c)) { has_alnum = true; continue; }
        if (c == '-' || c == '.' || c == ':' || c == '_') continue;
        return false;
    }
    return has_alnum;
}

namespace {

bool ipv4_non_public(std::uint32_t a) {
    const auto in = [a](std::uint32_t net, int bits) {
        return (a >> (32 - bits)) == (net >> (32 - bits));
    };
    return in(0x00000000u, 8)      // 0.0.0.0/8       "this" network
        || in(0x0A000000u, 8)      // 10.0.0.0/8      private
        || in(0x64400000u, 10)     // 100.64.0.0/10   carrier-grade NAT
        || in(0x7F000000u, 8)      // 127.0.0.0/8     loopback
        || in(0xA9FE0000u, 16)     // 169.254.0.0/16  link-local
        || in(0xAC100000u, 12)     // 172.16.0.0/12   private
        || in(0xC0000000u, 24)     // 192.0.0.0/24    IETF protocol assignments
        || in(0xC0000200u, 24)     // 192.0.2.0/24    documentation
        || in(0xC0A80000u, 16)     // 192.168.0.0/16  private
        || in(0xC6120000u, 15)     // 198.18.0.0/15   benchmarking
        || in(0xC6336400u, 24)     // 198.51.100.0/24 documentation
        || in(0xCB007100u, 24)     // 203.0.113.0/24  documentation
        || in(0xE0000000u, 4)      // 224.0.0.0/4     multicast
        || in(0xF0000000u, 4);     // 240.0.0.0/4     reserved + broadcast
}

}  // namespace

bool is_non_public_ip(std::string_view host) {
    std::string h(host);
    if (!h.empty() && h.front() == '[' && h.back() == ']') h = h.substr(1, h.size() - 2);
    if (h.empty() || h.size() > 64) return false;

    in_addr v4{};
    if (inet_pton(AF_INET, h.c_str(), &v4) == 1) return ipv4_non_public(ntohl(v4.s_addr));

    in6_addr v6{};
    if (inet_pton(AF_INET6, h.c_str(), &v6) != 1) return false;  // a hostname
    const unsigned char* b = v6.s6_addr;
    const auto zero_prefix = [b](int n) {
        for (int i = 0; i < n; ++i)
            if (b[i]) return false;
        return true;
    };
    if (zero_prefix(15) && (b[15] == 0 || b[15] == 1)) return true;    // :: and ::1
    if (zero_prefix(10) && b[10] == 0xff && b[11] == 0xff) {           // ::ffff:a.b.c.d
        const std::uint32_t a = (std::uint32_t(b[12]) << 24) | (std::uint32_t(b[13]) << 16) |
                                (std::uint32_t(b[14]) << 8) | b[15];
        return ipv4_non_public(a);
    }
    if (zero_prefix(12)) return true;                                   // ::a.b.c.d (deprecated)
    if (b[0] == 0 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b) {   // 64:ff9b::/96 NAT64
        const std::uint32_t a = (std::uint32_t(b[12]) << 24) | (std::uint32_t(b[13]) << 16) |
                                (std::uint32_t(b[14]) << 8) | b[15];
        return ipv4_non_public(a);
    }
    if ((b[0] & 0xfe) == 0xfc) return true;                             // fc00::/7  ULA
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return true;             // fe80::/10 link-local
    if (b[0] == 0xff) return true;                                      // ff00::/8  multicast
    if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return true;  // 2001:db8::/32
    return false;
}

std::optional<Address> parse_address(std::string_view raw, std::uint16_t default_port) {
    const std::string in = trim(raw);
    if (in.empty() || in.size() > 300) return std::nullopt;
    // No schemes, paths, credentials or non-printable bytes.
    for (unsigned char c : in) {
        if (c <= 0x20 || c >= 0x7f) return std::nullopt;
        if (c == '/' || c == '\\' || c == '@' || c == '?' || c == '#' || c == ',') return std::nullopt;
    }

    Address a;
    if (in.front() == '[') {
        const auto close = in.find(']');
        if (close == std::string::npos || close == 1) return std::nullopt;
        a.host = in.substr(1, close - 1);
        a.ipv6_literal = true;
        const std::string rest = in.substr(close + 1);
        if (rest.empty()) {
            if (!default_port) return std::nullopt;
            a.port = default_port;
        } else {
            if (rest.front() != ':' || !parse_port(std::string_view(rest).substr(1), a.port))
                return std::nullopt;
        }
    } else if (std::count(in.begin(), in.end(), ':') > 1) {
        // Bare IPv6 literal without brackets: no port can be attached.
        if (!default_port) return std::nullopt;
        a.host = in;
        a.ipv6_literal = true;
        a.port = default_port;
    } else {
        const auto colon = in.find(':');
        if (colon == std::string::npos) {
            if (!default_port) return std::nullopt;
            a.host = in;
            a.port = default_port;
        } else {
            a.host = in.substr(0, colon);
            if (!parse_port(std::string_view(in).substr(colon + 1), a.port)) return std::nullopt;
        }
    }
    if (!is_valid_hostname(a.host)) return std::nullopt;
    a.host = to_lower(a.host);
    return a;
}

bool is_valid_fingerprint(std::string_view fp) {
    if (fp.size() < 32 || fp.size() > 128) return false;
    for (char c : fp) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return true;
}

bool is_uuid_v4(std::string_view s) {
    if (s.size() != 36) return false;
    for (std::size_t i = 0; i < 36; ++i) {
        const char c = s[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') return false;
            continue;
        }
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    if (s[14] != '4') return false;
    const char v = static_cast<char>(std::tolower(static_cast<unsigned char>(s[19])));
    return v == '8' || v == '9' || v == 'a' || v == 'b';
}

namespace {

// Confusables (I/L -> 1, O -> 0) are folded in every group before charset
// checks: a hand-copied 0 read as O must round-trip in the hint groups just
// as it does in the entropy groups.
void fold_confusables(std::string& g) {
    for (char& c : g) {
        if (c == 'I' || c == 'L') c = '1';
        else if (c == 'O') c = '0';
    }
}

// Crockford base32 excludes I, L, O (folded above) and U entirely.
bool is_crockford_group(const std::string& g) {
    for (char c : g) {
        const bool ok = (c >= '0' && c <= '9') ||
                        (c >= 'A' && c <= 'Z' && c != 'I' && c != 'L' && c != 'O' && c != 'U');
        if (!ok) return false;
    }
    return true;
}

bool is_hex_group(const std::string& g) {
    for (char c : g)
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) return false;
    return true;
}

}  // namespace

std::string normalize_invite_code(std::string_view s) {
    const std::string t = trim(s);
    // Legacy codes are UUID v4 and stay lowercase, exactly as stored.
    if (t.size() == 36) {
        std::string low = to_lower(t);
        return is_uuid_v4(low) ? low : std::string{};
    }

    std::string up;
    up.reserve(t.size());
    for (char c : t) up += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    if (!starts_with(up, "R2R-")) return {};

    std::vector<std::string> groups;
    std::string cur;
    for (std::size_t i = 4; i <= up.size(); ++i) {
        if (i == up.size() || up[i] == '-') {
            if (cur.size() != 4) return {};
            groups.push_back(cur);
            cur.clear();
        } else {
            cur += up[i];
        }
    }

    // 3 groups: bare code, all entropy. 5 groups: two hex hint groups first.
    if (groups.size() != 3 && groups.size() != 5) return {};
    const std::size_t entropy_from = groups.size() - 3;
    for (auto& g : groups) fold_confusables(g);
    for (std::size_t i = 0; i < entropy_from; ++i)
        if (!is_hex_group(groups[i])) return {};
    for (std::size_t i = entropy_from; i < groups.size(); ++i)
        if (!is_crockford_group(groups[i])) return {};

    std::string out = "R2R";
    for (const auto& g : groups) out += "-" + g;
    return out;
}

std::string invite_hint_ip(std::string_view canonical_code) {
    // "R2R-AAAA-BBBB-XXXX-XXXX-XXXX": the two hex groups are an IPv4.
    if (canonical_code.size() != 28 || !starts_with(canonical_code, "R2R-")) return {};
    const std::string hex = std::string(canonical_code.substr(4, 4)) +
                            std::string(canonical_code.substr(9, 4));
    std::string out;
    for (int i = 0; i < 4; ++i) {
        int v = 0;
        for (int j = 0; j < 2; ++j) {
            const char c = hex[static_cast<std::size_t>(i * 2 + j)];
            v = v * 16 + (c <= '9' ? c - '0' : c - 'A' + 10);
        }
        if (i) out += '.';
        out += std::to_string(v);
    }
    return out;
}

std::string ipv4_hint_hex(std::string_view host) {
    // A hint must be typeable, so only literal IPv4 qualifies: four decimal
    // octets, rendered as 8 uppercase hex characters.
    unsigned parts[4];
    int filled = 0;
    unsigned cur = 0;
    int digits = 0;
    for (std::size_t i = 0; i <= host.size(); ++i) {
        if (i == host.size() || host[i] == '.') {
            if (!digits || filled == 4 || cur > 255) return {};
            parts[filled++] = cur;
            cur = 0;
            digits = 0;
        } else if (host[i] >= '0' && host[i] <= '9') {
            if (++digits > 3) return {};
            cur = cur * 10 + static_cast<unsigned>(host[i] - '0');
        } else {
            return {};
        }
    }
    if (filled != 4) return {};
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (int i = 0; i < 4; ++i) {
        out += hex[parts[i] >> 4];
        out += hex[parts[i] & 0xf];
    }
    return out;
}

// ---------------------------------------------------------- filesystem -----

bool file_exists(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
}

bool is_safe_filename(std::string_view name) {
    if (name.empty() || name.size() > 128) return false;
    if (name == "." || name == "..") return false;
    if (name.front() == '.') return false;
    for (unsigned char c : name) {
        if (c <= 0x20 || c >= 0x7f) return false;
        if (c == '/' || c == '\\') return false;
    }
    return true;
}

std::vector<std::string> list_dirs(const std::string& dir) {
    std::vector<std::string> out;
    DIR* d = ::opendir(dir.c_str());
    if (!d) return out;
    while (struct dirent* e = ::readdir(d)) {
        const std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        struct stat st{};
        if (::stat(path_join(dir, name).c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) out.push_back(name);
    }
    ::closedir(d);
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<DirEntry> list_files(const std::string& dir) {
    std::vector<DirEntry> out;
    DIR* d = ::opendir(dir.c_str());
    if (!d) return out;
    while (struct dirent* e = ::readdir(d)) {
        const std::string name = e->d_name;
        if (!is_safe_filename(name)) continue;
        struct stat st{};
        if (::stat(path_join(dir, name).c_str(), &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;
        out.push_back({name, static_cast<std::int64_t>(st.st_size),
                       static_cast<std::int64_t>(st.st_mtime)});
    }
    ::closedir(d);
    std::sort(out.begin(), out.end(),
              [](const DirEntry& a, const DirEntry& b) { return a.name < b.name; });
    return out;
}

std::string dirname_of(const std::string& path) {
    const auto pos = path.find_last_of('/');
    if (pos == std::string::npos) return ".";
    if (pos == 0) return "/";
    return path.substr(0, pos);
}

std::string path_join(std::string_view a, std::string_view b) {
    if (a.empty()) return std::string(b);
    if (!b.empty() && b.front() == '/') return std::string(b);
    std::string out(a);
    if (out.back() != '/') out += '/';
    out += b;
    return out;
}

bool make_dirs(const std::string& path, unsigned mode) {
    if (path.empty() || path == "." || path == "/") return true;
    std::string cur;
    if (path.front() == '/') cur = "/";
    for (auto& part : split(path, '/')) {
        if (part.empty()) continue;
        if (cur.size() > 1 || (cur.size() == 1 && cur[0] != '/')) cur += '/';
        cur += part;
        if (::mkdir(cur.c_str(), static_cast<mode_t>(mode)) != 0 && errno != EEXIST) return false;
    }
    return true;
}

std::optional<std::string> read_file(const std::string& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return std::nullopt;
    std::string data;
    char buf[16384];
    ssize_t n;
    while ((n = ::read(fd, buf, sizeof buf)) > 0) data.append(buf, static_cast<std::size_t>(n));
    const bool ok = (n == 0);
    ::close(fd);
    if (!ok) return std::nullopt;
    return data;
}

bool write_file_atomic(const std::string& path, std::string_view data, unsigned mode) {
    const std::string dir = dirname_of(path);
    const std::string tmp = path + ".tmp." + std::to_string(::getpid());

    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                          static_cast<mode_t>(mode));
    if (fd < 0) return false;
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n <= 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            ::unlink(tmp.c_str());
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0) { ::close(fd); ::unlink(tmp.c_str()); return false; }
    ::fchmod(fd, static_cast<mode_t>(mode));
    ::close(fd);

    if (::rename(tmp.c_str(), path.c_str()) != 0) { ::unlink(tmp.c_str()); return false; }

    // Persist the directory entry too, so the rename survives a crash.
    const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) { ::fsync(dfd); ::close(dfd); }
    return true;
}

// -------------------------------------------------------- rate limiting ----

bool TokenBucket::consume(double n, std::int64_t now_ms) {
    if (rate_ <= 0.0) return true;  // limiter disabled
    if (last_ms_ == 0) last_ms_ = now_ms;
    const std::int64_t dt = now_ms - last_ms_;
    if (dt > 0) {
        tokens_ = std::min(cap_, tokens_ + rate_ * (static_cast<double>(dt) / 1000.0));
        last_ms_ = now_ms;
    }
    if (tokens_ < n) return false;
    tokens_ -= n;
    return true;
}

}  // namespace r2r::util
