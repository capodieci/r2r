#include "onion.hpp"

#include <nlohmann/json.hpp>

#include "crypto.hpp"
#include "log.hpp"
#include "protocol.hpp"

using nlohmann::json;

namespace r2r::onion {

std::optional<Layer> parse(const util::Bytes& pt, std::size_t max_body) {
    if (pt.empty()) return std::nullopt;
    Layer layer;

    if (pt[0] == kRouting) {
        if (pt.size() < 2) return std::nullopt;
        const std::size_t n = pt[1];
        if (n == 0 || n > crypto::kMaxSlots) return std::nullopt;
        std::size_t off = 2;
        for (std::size_t i = 0; i < n; ++i) {
            if (off >= pt.size()) return std::nullopt;
            const std::size_t len = pt[off++];
            if (len == 0 || off + len > pt.size()) return std::nullopt;
            const std::string raw(pt.begin() + static_cast<std::ptrdiff_t>(off),
                                  pt.begin() + static_cast<std::ptrdiff_t>(off + len));
            off += len;
            auto addr = util::parse_address(raw, 8787);
            if (!addr) return std::nullopt;
            layer.next.push_back(addr->str());
        }
        layer.inner.assign(pt.begin() + static_cast<std::ptrdiff_t>(off), pt.end());
        if (layer.inner.size() < crypto::kMultiMin) return std::nullopt;
        return layer;
    }

    if (pt[0] != kTerminal || pt.size() < 3) return std::nullopt;
    const std::size_t mlen = (static_cast<std::size_t>(pt[1]) << 8) | pt[2];
    if (mlen == 0 || 3 + mlen > pt.size()) return std::nullopt;
    const json meta = json::parse(pt.begin() + 3, pt.begin() + static_cast<std::ptrdiff_t>(3 + mlen),
                                  nullptr, false);
    if (meta.is_discarded() || !meta.is_object() || !meta.contains("to") || !meta["to"].is_string())
        return std::nullopt;
    auto target = proto::parse_target(meta["to"].get<std::string>());
    if (!target.valid) return std::nullopt;

    layer.terminal = true;
    layer.deliver.to = target.fingerprint;
    layer.deliver.home = target.relay;
    layer.deliver.body.assign(pt.begin() + static_cast<std::ptrdiff_t>(3 + mlen), pt.end());
    if (layer.deliver.body.empty() || layer.deliver.body.size() > max_body) return std::nullopt;
    if (meta.contains("id") && meta["id"].is_string()) layer.deliver.msg_id = meta["id"].get<std::string>();
    if (meta.contains("hint") && meta["hint"].is_string())
        layer.deliver.from_hint = meta["hint"].get<std::string>();
    if (layer.deliver.msg_id.empty()) layer.deliver.msg_id = crypto::uuid_v4();
    if (!util::is_uuid_v4(layer.deliver.msg_id)) return std::nullopt;
    if (layer.deliver.from_hint.size() > 128) layer.deliver.from_hint.clear();
    return layer;
}

std::optional<util::Bytes> build(const std::vector<std::vector<Hop>>& sets, const Terminal& terminal) {
    if (sets.empty() || sets.size() > kMaxLayers) return std::nullopt;

    json meta{{"to", terminal.home.empty() ? terminal.to : terminal.to + "@" + terminal.home},
              {"id", terminal.msg_id.empty() ? crypto::uuid_v4() : terminal.msg_id}};
    if (!terminal.from_hint.empty()) meta["hint"] = terminal.from_hint;
    const std::string m = meta.dump();
    if (m.size() > 0xffff) return std::nullopt;

    util::Bytes pt;
    pt.push_back(kTerminal);
    pt.push_back(static_cast<std::uint8_t>(m.size() >> 8));
    pt.push_back(static_cast<std::uint8_t>(m.size() & 0xff));
    pt.insert(pt.end(), m.begin(), m.end());
    pt.insert(pt.end(), terminal.body.begin(), terminal.body.end());

    util::Bytes blob;
    // Seal from the innermost position outwards.
    for (std::size_t i = sets.size(); i-- > 0;) {
        const auto& set = sets[i];
        if (set.empty() || set.size() > crypto::kMaxSlots) return std::nullopt;
        std::vector<util::Bytes> keys;
        for (const auto& h : set) {
            auto key = util::b64_decode(h.x25519_b64);
            if (!key || key->size() != crypto::kPubLen) {
                log::error("onion: hop ", h.address, " has no usable x25519 key");
                return std::nullopt;
            }
            keys.push_back(std::move(*key));
        }
        auto sealed = crypto::seal_multi(keys, pt);
        if (!sealed) return std::nullopt;
        blob = std::move(*sealed);
        if (i == 0) break;

        // The layer for position i-1 names the candidates of position i.
        pt.clear();
        pt.push_back(kRouting);
        pt.push_back(static_cast<std::uint8_t>(set.size()));
        for (const auto& h : set) {
            if (h.address.empty() || h.address.size() > 255) return std::nullopt;
            pt.push_back(static_cast<std::uint8_t>(h.address.size()));
            pt.insert(pt.end(), h.address.begin(), h.address.end());
        }
        pt.insert(pt.end(), blob.begin(), blob.end());
    }
    return blob;
}

}  // namespace r2r::onion
