// r2r-vectors -- known-answer test vectors for re-implementations of the relay.
//
// Prints one JSON document (docs/protocol-vectors.json) that a port of the
// relay in another language can check itself against before it ever talks to
// the network: encodings, identity derivations, canonical signing strings and
// signatures, HMAC/TURN credentials, the sealed box, the multi-recipient onion
// layer, complete onion routes, target parsing and invite-code formats.
//
// Every value is a function of the fixed inputs embedded below. Primitives
// that draw randomness (a sealed box takes an ephemeral key and a nonce) were
// run ONCE and their output embedded as hex constants, so two runs of this
// program print identical documents. `--regen` draws those blobs afresh, uses
// them for this run, and prints replacement C++ constants to stderr.
//
// The program also asserts every value that docs/R2R-WHITEPAPER.md Appendix A
// lists for the same inputs; a mismatch is a hard failure, so a successful run
// is also a self-test of libr2r_core against the white paper.
//
//   cmake -S . -B build -DR2R_BUILD_VECTORS=ON
//   cmake --build build --target r2r-vectors
//   ./build/r2r-vectors > docs/protocol-vectors.json
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "crypto.hpp"
#include "onion.hpp"
#include "protocol.hpp"
#include "util.hpp"

namespace {

using nlohmann::json;
using r2r::util::Bytes;
namespace crypto = r2r::crypto;
namespace onion = r2r::onion;
namespace proto = r2r::proto;
namespace util = r2r::util;

// ---- fixed inputs ----------------------------------------------------------

constexpr std::int64_t kTs = 1754331000;
constexpr const char* kNonce = "00112233445566778899aabb";
constexpr const char* kAdvertiseA = "203.0.113.10:8787";
constexpr const char* kAdvertiseB = "198.51.100.20:8787";
constexpr const char* kAdvertiseC = "relay-c.example:8788";
constexpr const char* kMsgId = "3b241101-e2bb-4255-8caf-4136c566a962";
constexpr const char* kTurnSecret = "s3cret";
constexpr std::int64_t kTurnTtl = 600;
constexpr std::size_t kMaxBody = 1u << 20;

// Seeds. Identity C and relays A/B are the white paper's Appendix A seeds so
// the two documents cross-check; the rest are simple fixed patterns.
constexpr const char* kSeedIdentityC = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr const char* kSeedRelayA = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
constexpr const char* kSeedRelayC = "9c1185a5c5e9fc54612808977ee8f548b2258d31f7e2b0a5a9b5d3c0e4f6a7b8";

// White paper Appendix A values, asserted below.
constexpr const char* kWpPubC_b64 = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
constexpr const char* kWpFpC = "06f080fd2509682e820cbdfd3b10fe45c39d6e16e89fb3e1c31ac71ae65f3b61";
constexpr const char* kWpChecksumC = "fdbd93";
constexpr const char* kWpAddressC =
    "R2R_AOQQPP7T_ZYIL4HLQ_3UMOOS6A_TFT6JVRQ_TOSQ2XY5_3SDGIESV_GG4P3PMT";
constexpr const char* kWpClientSigC =
    "VNWhTQV1+deh6G5QBBNqbAE0qi5VhE6b2z3dmMgyv0sz2eW29XxMFKZM1NOel9NN7A1OOUpikQh4ldiNY+hrBg==";
constexpr const char* kWpAuthHeaderC =
    "eyJpZCI6IjA2ZjA4MGZkMjUwOTY4MmU4MjBjYmRmZDNiMTBmZTQ1YzM5ZDZlMTZlODlmYjNlMWMzMWFjNzFhZTY1ZjNiNjEiLCJwdWJrZXkiOiJBNkVIdi9QT0VMNGRjTjBZNTB2QW1XZmsxakNicFExZkhkeUdaQkpWTWJnPSIsInRzIjoxNzU0MzMxMDAwLCJub25jZSI6IjAwMTEyMjMzNDQ1NTY2Nzc4ODk5YWFiYiIsInNpZyI6IlZOV2hUUVYxK2RlaDZHNVFCQk5xYkFFMHFpNVZoRTZiMnozZG1NZ3l2MHN6MmVXMjlYeE1GS1pNMU5PZWw5Tk43QTFPT1VwaWtRaDRsZGlOWStockJnPT0ifQ==";
constexpr const char* kWpRelayAEd_b64 = "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=";
constexpr const char* kWpRelayANodeId = "e3331ed6dce0d2adba2dbd8e7605915f";
constexpr const char* kWpRelayAXPriv = "1a23ab6fb70bf0e5ddc656e86da68e35b07a0db11d9c2cf602ce59f915560889";
constexpr const char* kWpRelayAX_b64 = "L6fz1qOQoL4X9s/7sTmojJs3hm/ncH3U2f1fOozaDWA=";
constexpr const char* kWpRelayBX_b64 = "yQGGpcx4wDNe9mX0Vvmya18A2lt3rLRoAVO2Pi/pRXM=";
constexpr const char* kWpHelloSig =
    "akKZzGzU902/jtD3kJg3vsFUqlilyPdtBV7AYr2/6Z3Icc8INsrtf9/R+ArhJygwZUqNYuuSShkBcg248T67AA==";
constexpr const char* kWpPointerSig =
    "OGU6MCys9S2WqI5RyVJCwEnKfnbIyzlNw9ogieS+xChwA448ERyJLQIlE37DKs48qlSAS1Qx754Z13cQV1AICA==";
constexpr const char* kWpCollectSig =
    "k+XKS9VwmE8txmLhpcPaDy8Stp2sIolaNT/IRjpK6cTG80aI0gu4Q4aU0pBSv1xOlWmMWborYN/okTU3+//jCA==";
constexpr const char* kWpTurnUsername = "1754331600:46ea36526cd6";
constexpr const char* kWpTurnCredential = "n6Ev6DcmiWtZAsoB2mRENLubSuU=";
// A.4: sealed box to relay A with eph_priv = 32 x 0x42 and nonce "defghijklmno".
constexpr const char* kWpSealEphPub = "132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472";
constexpr const char* kWpSealShared = "1ade2d30742f253a94c2288399f519ce286d87a05b54d728ff78bbfcc6922557";
constexpr const char* kWpSealKey = "248220de10b4d4b25851948f96371c571686268d83426c388d558c1f8a6c2caa";
constexpr const char* kWpSealPlain =
    R"({"v":1,"deliver":{"to":"06f080fd2509682e820cbdfd3b10fe45c39d6e16e89fb3e1c31ac71ae65f3b61","id":"3b241101-e2bb-4255-8caf-4136c566a962","body":"aGVsbG8="}})";
constexpr const char* kWpSealBlob_b64 =
    "ARMsRCvgEPvVfnJgMyiqducfzMFQOq4hkyfRTZyZk/RyZGVmZ2hpamtsbW5vOG18Tfwq3K+F5XaPO2Mxp6wKTmp+BQSRQgrI"
    "GYMtSfIByU1HSFwUyBims+nammZef9GtxDvZPzFnlvffJobqKTCWnN13Z4SmpYsiSSJ5rjlqt9y7TpYDFRBwqZaGcHdcPPy8"
    "P9d0Al76VBzrzz3PBjfnOd+OT8csOmGzQNXJN+OtQ4ARIsOFZ0Vdp3q+LFgxGRU1byS9S67QybxSJ97cOAKbBjm9d0v80g==";
// A.4b: a terminal layer sealed to relays A and B by the wallet's JavaScript.
constexpr const char* kWpLayer_b64 =
    "AgIBEyxEK+AQ+9V+cmAzKKp25x/MwVA6riGTJ9FNnJmT9HIBAQEBAQEBAQEBAQEXWj7PQQ1tUqe8HnOLOM9rUOT/nUlc2Kzh"
    "6Ahh2jE6gQHBzvBCTlp64Sxm4phMTI0Bze/YeDqRtEZkDi4flVmds15ISgBxvSGCs7YNCBLBDHACAgICAgICAgICAgJk5wMF"
    "WGBFh+18Vwnd+3DOECG7yM48BiHDSd27JmIDWbwLs3xbMv0YvnHn6UNaoglmZmZmZmZmZmZmZmY9vTkpV2hGa/pLIDPBmMZS"
    "SVBZZw1Nl3BV7qdWEKwdcFNgTvLIF/zCJNQG/o2FbRp537Ri2Jyasssma4UapTi0ktn22fXGsRCWBpe2ccpgaVNzzYu3VUzX"
    "DcIqsCBHWfYJBId59wvrmPYUzmHPT5cFupNZkWwGyVRwikViCccl++uSZpWAJgzvb1iDGNCirjTf+OPTeXbTJabrlFQc7kQ=";
constexpr const char* kWpLayerPlainHex =
    "0200877b22746f223a2230366630383066643235303936383265383230636264666433623130666534356333396436"
    "653136653839666233653163333161633731616536356633623631403230332e302e3131332e31303a38373837222c"
    "226964223a2233623234313130312d653262622d343235352d386361662d343133366335363661393632227d68656c"
    "6c6f";

// ---- once-generated blobs (see --regen) ------------------------------------
// The library draws an ephemeral key and a nonce for each sealed slot, so these
// cannot be recomputed from the inputs alone; they were produced once by the
// functions named here and are now fixed inputs that the relays below open.

// crypto::seal(relay_a.x_pub, kSealPlain)
constexpr const char* kSealPlain = "r2r sealed-box vector: plaintext for relay A";
constexpr const char* kSealBlobHex =
    "01e9348220c6b4b2bed85ad6749f073bc02983a027e33640bb26484455331659098ff7c90e4838709c8cb067746c1623"
    "f2edebb4da098d506b39659c9ea05ac47a1699761eabf8fd91a84d7731988781db07780594b3fed5c7a7bcf68ef93f89"
    "b710aeb415652675dc";

// crypto::seal_multi({relay_a.x_pub, relay_b.x_pub}, kMultiPlain)
constexpr const char* kMultiPlain = "r2r multi-recipient layer vector: relay A or relay B may open this";
constexpr const char* kMultiBlobHex =
    "02020113134ac24b55009c7df64bdb94f0e4df7dcaedd0e5a4921726972d1711ef274ad317102c4d17f94df835cfd7ae"
    "daccef0deca488ecab115f61cc9b65d5067e394299af7e019b40578bd43ba0ef821b0878719cbddbbf365425c64f1201"
    "2df77186c2361cd1ab7f45e9c9c9416cae4b656fad5b666fd1e57bdd13c45d551276d74947ac94c222b4e01eefe074fa"
    "e401d5eda536cd668ce3e4481cb955569f9c3b03f8e523a04d5dfbbc25d978db3a1d22375510d31dbb3aa604fcb36ae0"
    "7a3d995b66ee1bab90025c57738959ebbe50aa533b074806bf0c6947cc2df6a60dc31ad0c2f665dcef645fc6d6bd5903"
    "64a7ce30b8388c4bb8061156715175ffc3a9de94343a535a9beabcd784e9907fcf508a2343521b743abd";

// onion::build({{A}, {B}}, terminal) and onion::build({{A}, {B, C}}, terminal)
constexpr const char* kOnionBody = "hello through the onion";
constexpr const char* kOnionHint = "vector";
constexpr const char* kOnionBlobHex =
    "02010163e28b18d15dba6d04b370dbd5d0dec1e6a7e7fe725240cb0af8c9406ed14f33b0850f95f21e134dbb64800bda"
    "ecd71058c9b2173287d1fac109ff267d63aedbe33c09e87b2bc878f3bde4ac475165fc44a4787295b630387f3b86a8b7"
    "418c57e9b8f8d509e9fcd7ce0027439f857def08531ab33e766e291a2c3135ac1fe23e5845659c0d217ea689e2f7e581"
    "ff0ec1b836adbe993e285917a13935acad3e0632226802579239d657afb848db695a5eda7045c5fb7684eaf09e38a3d5"
    "90f8897ccf1710627023264eee37c93f729a332bbd2ee5f173f4a39963607d258ad61bb3d19db923946cd740e90244c3"
    "80e0a440d09850e92edfe87cc0df9c28f313fdd3ef5e988fbd6759c6598369be59692ca15df0283a4d761f8803a018d8"
    "9550de7a05788310581f814719f0468a483308f059b92e645788ed5c1a3a4793ade775c48f5f71e29924d7c3b35cc106"
    "910d10206114cce8eda9860f07993ae58a9d789e7c9f845a5154eb4e12d95e47074488dd8a5ec6891f19ba90b8dd4851"
    "c3ae1c296fec35d33d171b7126dece81cc22bdd6e13d7811edeb4552017af1346f84e0acde6aad102d1eb0b68fa0058b"
    "982561b470546ae2e2a465cd80";
constexpr const char* kOnion2BlobHex =
    "020101d636e40643b655169e0f5a72a9d3c6d6e98c0759ce2527d93b0896a40847a87e315d5c7b7683cde1216ac5ea12"
    "5cc237be40293ffd56ad8d718d77ffbe45914c19a3418087797a2ca7639acb0c9fc211a2fd026509d87d80d9cf06d052"
    "300d2bd9b0332d3db84170a12a2da094b4e7d71eb269535813df54488dea7c6761db67a09bc020805ba614ee89c3923a"
    "aaa114fcce40e2c13d1d550a72302cc6a0ff56102da598488f372b1ec608851f82016f942a8e75495015e63587ca64f8"
    "39a540bb07b81d6b1f1999d3b8e9d11bafe560c495bac1efec1ff25b20f1cac04cb6e0eebb882081f1e568c453c8a1ba"
    "a97291bde94a44a8edb0f19a62afd966c516ae085b8ee8a0e8c8ab16fe552f78716cabe7143557ec45cf37abea5e6593"
    "eac1778b0752a859899217666297dc68ae0ae84a80dfd638b6f4a7b504aca4ce2444542cf864d3700e54c563b0554353"
    "a13cab6b8a3cf7f99a3ff09171a493472fb6390dee277c08ca34c91a28883c3c1cb36bc27ee0c75db3045816cb4c4199"
    "e567759dc610191163df7e79a5cf214f20c416600d653dc9bd64b3839bf664fd7580a456c448620ff5eb0ac16cdce191"
    "0be8bb3b6903dbaf91925019f6c2c1814c1787a7fed9a2634089bc138952c0aa229b86d13f95a04fb709e1bb2fa21a2e"
    "e5bafbdf3d9cc01c01e56c15606827348b0292099b1eb564e302c5fe451bf46df646ead3d78eddc3a5434d6db1a6c244"
    "1c1d06e80f82a8e7fcda391e5ce173b3cf7c2a77cbf0f17b481c32a1b7c746";

// ---- helpers ---------------------------------------------------------------

[[noreturn]] void fail(const std::string& what) {
    std::cerr << "r2r-vectors: " << what << "\n";
    std::exit(1);
}

void check(bool ok, const std::string& what) {
    if (!ok) fail("self-check failed: " + what);
}

Bytes hx(std::string_view h) {
    auto d = util::hex_decode(h);
    if (!d) fail("bad hex constant: " + std::string(h));
    return *d;
}

std::string hex(const Bytes& b) { return util::hex_encode(b); }
std::string b64(const Bytes& b) { return util::b64_encode(b); }
Bytes bytes_of(std::string_view s) { return Bytes(s.begin(), s.end()); }
std::string str_of(const Bytes& b) { return std::string(b.begin(), b.end()); }
Bytes slice(const Bytes& b, std::size_t from, std::size_t len) {
    if (from + len > b.size()) fail("slice out of range");
    return Bytes(b.begin() + static_cast<std::ptrdiff_t>(from),
                 b.begin() + static_cast<std::ptrdiff_t>(from + len));
}

Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

crypto::NodeIdentity node(const Bytes& seed) {
    auto n = crypto::NodeIdentity::from_seed(seed);
    if (!n) fail("NodeIdentity::from_seed rejected a 32-byte seed");
    return std::move(*n);
}

Bytes sign(const crypto::NodeIdentity& key, std::string_view msg) {
    auto s = key.sign(msg);
    if (!s) fail("sign failed");
    return *s;
}

json bytes_json(const Bytes& b) {
    return json{{"hex", hex(b)}, {"base64", b64(b)}, {"len", b.size()}};
}

// The relay's own check of a client proof (Hub::verify_client_proof), minus
// the |now - ts| <= 600 s clock window, which fixed vectors cannot satisfy.
std::string client_proof_verdict(const json& f) {
    const std::string id = util::to_lower(util::trim(f.value("id", std::string{})));
    const std::string pub_b64 = f.value("pubkey", std::string{});
    const std::string sig_b64 = f.value("sig", std::string{});
    const std::string nonce = f.value("nonce", std::string{});
    const std::int64_t ts = f.value("ts", std::int64_t{0});
    if (!util::is_valid_fingerprint(id)) return proto::kErrBadField;
    if (pub_b64.empty() || sig_b64.empty() || nonce.size() < 16 || nonce.size() > 64)
        return proto::kErrNotAuthorised;
    auto pub = util::b64_decode(pub_b64);
    auto sig = util::b64_decode(sig_b64);
    if (!pub || pub->size() != crypto::kPubLen || !sig) return proto::kErrNotAuthorised;
    if (crypto::fingerprint(*pub) != id) return proto::kErrNotAuthorised;
    if (!crypto::verify_signature(*pub, proto::client_auth_string(id, ts, nonce), *sig))
        return proto::kErrNotAuthorised;
    return "accept";
}

// ---- OpenSSL primitives used only to expose intermediate values ------------
// The library keeps HKDF and the sealing internals private; these reproduce
// them so the document can show x25519 private keys and a sealed box whose
// every intermediate is stated. Each result is verified through the public
// crypto:: API, so a divergence here would fail the run, not mislead a port.

Bytes ossl_hkdf_sha256(const Bytes& ikm, const Bytes& salt, std::string_view info, std::size_t out_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    check(ctx != nullptr, "HKDF context");
    Bytes out(out_len);
    std::size_t len = out_len;
    bool ok = EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
              EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm.data(), static_cast<int>(ikm.size())) > 0;
    if (ok && !salt.empty())
        ok = EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), static_cast<int>(salt.size())) > 0;
    ok = ok && EVP_PKEY_CTX_add1_hkdf_info(ctx, reinterpret_cast<const unsigned char*>(info.data()),
                                           static_cast<int>(info.size())) > 0 &&
         EVP_PKEY_derive(ctx, out.data(), &len) > 0 && len == out_len;
    EVP_PKEY_CTX_free(ctx);
    check(ok, "HKDF derive");
    return out;
}

Bytes ossl_x25519_pub(const Bytes& priv) {
    EVP_PKEY* k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), priv.size());
    check(k != nullptr, "x25519 private key");
    Bytes pub(32);
    std::size_t len = 32;
    const bool ok = EVP_PKEY_get_raw_public_key(k, pub.data(), &len) > 0 && len == 32;
    EVP_PKEY_free(k);
    check(ok, "x25519 public key");
    return pub;
}

Bytes ossl_x25519_shared(const Bytes& priv, const Bytes& peer_pub) {
    EVP_PKEY* k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), priv.size());
    EVP_PKEY* p = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), peer_pub.size());
    check(k != nullptr && p != nullptr, "x25519 keys");
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(k, nullptr);
    Bytes out(32);
    std::size_t len = 32;
    const bool ok = ctx != nullptr && EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_derive_set_peer(ctx, p) > 0 &&
                    EVP_PKEY_derive(ctx, out.data(), &len) > 0 && len == 32;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(k);
    EVP_PKEY_free(p);
    check(ok, "x25519 shared secret");
    return out;
}

// Returns ciphertext || 16-byte tag.
Bytes ossl_aes256gcm_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad, const Bytes& pt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    check(ctx != nullptr, "cipher context");
    Bytes out(pt.size() + crypto::kTagLen);
    int outl = 0;
    int total = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) == 1;
    if (ok && !aad.empty())
        ok = EVP_EncryptUpdate(ctx, nullptr, &outl, aad.data(), static_cast<int>(aad.size())) == 1;
    outl = 0;
    if (ok && !pt.empty()) {
        ok = EVP_EncryptUpdate(ctx, out.data(), &outl, pt.data(), static_cast<int>(pt.size())) == 1;
        total = outl;
    }
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, out.data() + total, &outl) == 1;
        total += outl;
    }
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(crypto::kTagLen),
                                   out.data() + total) == 1;
    EVP_CIPHER_CTX_free(ctx);
    check(ok, "AES-256-GCM encrypt");
    out.resize(static_cast<std::size_t>(total) + crypto::kTagLen);
    return out;
}

Bytes ossl_sha3_256(const Bytes& in) {
    Bytes out(32);
    unsigned int len = 32;
    check(EVP_Digest(in.data(), in.size(), out.data(), &len, EVP_sha3_256(), nullptr) == 1 && len == 32,
          "SHA3-256");
    return out;
}

// crypto::seal with a caller-chosen ephemeral key and nonce, exposing every
// intermediate (white paper section 10.2).
struct SealTrace {
    Bytes eph_pub, shared, salt, key, aad, ct_tag, blob;
};

SealTrace seal_fixed(const Bytes& recipient_pub, const Bytes& eph_priv, const Bytes& nonce, const Bytes& pt) {
    SealTrace t;
    t.eph_pub = ossl_x25519_pub(eph_priv);
    t.shared = ossl_x25519_shared(eph_priv, recipient_pub);
    t.salt = cat({t.eph_pub, recipient_pub});
    t.key = ossl_hkdf_sha256(t.shared, t.salt, "r2r-seal-v1", 32);
    t.aad = cat({Bytes{0x01}, t.eph_pub, recipient_pub});
    t.ct_tag = ossl_aes256gcm_encrypt(t.key, nonce, t.aad, pt);
    t.blob = cat({Bytes{0x01}, t.eph_pub, nonce, t.ct_tag});
    return t;
}

// The invite-code entropy encoding, reproduced from crypto::invite_code so
// the document can show it on fixed entropy (the library only draws random).
std::string crockford_code(const Bytes& entropy8, const std::string& hint_hex) {
    static const char kAlphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | entropy8[static_cast<std::size_t>(i)];
    std::string code = "R2R-";
    if (hint_hex.size() == 8) code += hint_hex.substr(0, 4) + "-" + hint_hex.substr(4, 4) + "-";
    for (int i = 0; i < 12; ++i) {
        if (i && i % 4 == 0) code += '-';
        code += kAlphabet[(v >> (55 - 5 * i)) & 0x1f];
    }
    return code;
}

void print_constant(const char* name, const Bytes& b) {
    const std::string h = hex(b);
    std::cerr << "constexpr const char* " << name << " =\n";
    for (std::size_t i = 0; i < h.size(); i += 96)
        std::cerr << "    \"" << h.substr(i, 96) << "\"" << (i + 96 >= h.size() ? ";\n" : "\n");
}

// ---- fixtures --------------------------------------------------------------

struct Fixtures {
    Bytes seed_id_a, seed_id_b, seed_id_c, seed_relay_a, seed_relay_b, seed_relay_c;
    crypto::NodeIdentity id_a, id_b, id_c, relay_a, relay_b, relay_c;
    std::string fp_a, fp_b, fp_c;
};

// ---- sections --------------------------------------------------------------

json section_meta() {
    json j;
    j["generated_by"] = "tools/protocol-vectors.cpp (r2r-relay " R2R_VERSION ")";
    j["openssl_version"] = crypto::openssl_version();
    j["purpose"] =
        "Known-answer vectors so that a re-implementation of the R2R relay in another language can "
        "prove byte-exact compatibility with the reference C++ relay's cryptography, canonical strings "
        "and encodings before it ever talks to the network.";
    j["regenerate"] =
        "cmake -S . -B build -DR2R_BUILD_VECTORS=ON && cmake --build build --target r2r-vectors && "
        "./build/r2r-vectors > docs/protocol-vectors.json";
    j["stability"] =
        "Every value is a function of the fixed inputs in the source. Blobs from randomised primitives "
        "(sealed boxes) were generated once and embedded as constants; the generator opens them with "
        "the public API on every run, and two runs print identical documents.";
    j["whitepaper"] =
        "docs/R2R-WHITEPAPER.md sections 3 (conventions), 4 (identities), 10 (onion) and Appendix A. "
        "Values marked whitepaper_ref reproduce Appendix A and are asserted by the generator.";
    j["conventions"] = {
        {"hex", "lowercase on output; decoders accept either case"},
        {"base64", "standard alphabet (A-Z a-z 0-9 + /) with '=' padding on output; decoders accept "
                   "standard and URL-safe alphabets, padded or not, and ignore \\n \\r space \\t"},
        {"integers", "Unix seconds as JSON integers; decimal ASCII inside signing strings"},
        {"strings", "UTF-8; '\\n' inside a signing string is the single byte 0x0a; no trailing newline"},
        {"json", "key order is never significant; the reference emits keys sorted alphabetically"},
        {"byte_order", "all multi-byte integers inside binary layouts are big-endian (len16be)"}};
    return j;
}

json section_encodings() {
    json j;
    j["verify"] =
        "base64_encode(bytes) == base64 and hex_encode(bytes) == hex for every case; decode each "
        "'decode_base64'/'decode_hex' input and compare 'accepted' and 'hex'.";
    j["hex_is_lowercase"] = true;
    j["base64_alphabet"] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    j["base64_padding"] = "=";

    json cases = json::array();
    auto add = [&](const Bytes& b, const char* note) {
        json c = bytes_json(b);
        c["note"] = note;
        cases.push_back(c);
    };
    add({}, "empty");
    add(bytes_of("f"), "RFC 4648 'f'");
    add(bytes_of("fo"), "RFC 4648 'fo'");
    add(bytes_of("foo"), "RFC 4648 'foo'");
    add(bytes_of("foob"), "RFC 4648 'foob'");
    add(bytes_of("fooba"), "RFC 4648 'fooba'");
    add(bytes_of("foobar"), "RFC 4648 'foobar'");
    add(hx("000102030405060708090a0b0c0d0e0f"), "bytes 0x00..0x0f");
    add(hx("fbff"), "exercises '+' and '/'");
    add(hx("fffefd"), "exercises '/'");
    add(hx("ff"), "single 0xff");
    j["encode"] = cases;

    json dec = json::array();
    auto add_dec = [&](const std::string& in, const char* note) {
        auto r = util::b64_decode(in);
        json c{{"input", in}, {"accepted", r.has_value()}, {"note", note}};
        c["hex"] = r ? json(hex(*r)) : json(nullptr);
        dec.push_back(c);
    };
    add_dec("+/8=", "standard alphabet, padded");
    add_dec("-_8", "URL-safe alphabet, unpadded");
    add_dec("-_8=", "URL-safe alphabet, padded");
    add_dec("Zm9v", "'foo'");
    add_dec("Zm9v\nYmFy", "embedded newline is ignored");
    add_dec("Zm9=", "non-zero leftover bits: rejected");
    add_dec("Zm9v=Zg", "data after padding: rejected");
    add_dec("Zm9v===", "more than two '=': rejected");
    add_dec("Zg", "'f' without padding: accepted");
    add_dec("Z", "6 leftover bits: rejected");
    add_dec("Zm*v", "character outside both alphabets: rejected");
    j["decode_base64"] = dec;

    json hdec = json::array();
    auto add_hex = [&](const std::string& in, const char* note) {
        auto r = util::hex_decode(in);
        json c{{"input", in}, {"accepted", r.has_value()}, {"note", note}};
        c["hex"] = r ? json(hex(*r)) : json(nullptr);
        hdec.push_back(c);
    };
    add_hex("FBFF", "uppercase input, lowercase output");
    add_hex("fbff", "lowercase");
    add_hex("fbf", "odd length: rejected");
    add_hex("zz", "non-hex: rejected");
    add_hex("", "empty: accepted as zero bytes");
    j["decode_hex"] = hdec;
    return j;
}

json identity_entry(const std::string& label, const Bytes& seed, const crypto::NodeIdentity& id) {
    json j;
    j["label"] = label;
    j["seed_hex"] = hex(seed);
    j["ed25519_pub_hex"] = hex(id.ed_pub());
    j["ed25519_pub_b64"] = id.ed_pub_b64();
    const std::string fp = crypto::fingerprint(id.ed_pub());
    j["fingerprint"] = fp;
    j["fingerprint_preimage_hex"] = hex(cat({bytes_of("r2r-id-v1"), id.ed_pub()}));
    const Bytes ck = slice(ossl_sha3_256(cat({id.ed_pub(), bytes_of("R2R")})), 0, 3);
    j["address_checksum_hex"] = hex(ck);
    j["address_raw_hex"] = hex(cat({id.ed_pub(), ck}));
    const std::string addr = crypto::contact_address(id.ed_pub());
    check(addr.size() == 3 + 7 * 9, "contact address length for " + label);
    j["contact_address"] = addr;

    // Decode cases. The decoder drops '_', '-' and ' ', uppercases, strips a
    // leading "R2R", and then needs exactly 56 base32 characters.
    const std::string groups = addr.substr(4);  // after "R2R_"
    std::string compact;
    for (char c : groups) if (c != '_') compact += c;
    check(compact.size() == 56, "56 base32 chars for " + label);
    std::string dashed = addr, spaced = addr;
    for (auto& c : dashed) if (c == '_') c = '-';
    for (auto& c : spaced) if (c == '_') c = ' ';
    std::string bad_checksum = addr;
    bad_checksum.back() = (bad_checksum.back() == 'A') ? 'B' : 'A';
    std::string bad_key = addr;
    bad_key[4] = (bad_key[4] == 'A') ? 'B' : 'A';
    std::string short_addr = addr.substr(0, addr.size() - 1);
    std::string bad_char = addr;
    bad_char[5] = '1';  // '1' is not in the RFC 4648 base32 alphabet

    json cases = json::array();
    auto add = [&](const std::string& in, const char* note) {
        auto r = crypto::pubkey_from_contact_address(in);
        json c{{"input", in}, {"accepted", r.has_value()}, {"note", note}};
        c["pubkey_hex"] = r ? json(hex(*r)) : json(nullptr);
        cases.push_back(c);
    };
    add(addr, "exact");
    add(util::to_lower(addr), "lowercase");
    add(dashed, "'-' separators");
    add(spaced, "space separators");
    add(compact, "no prefix, no separators");
    add("r2r-" + util::to_lower(dashed.substr(4)), "lowercase with 'r2r-' prefix");
    add(bad_checksum, "last character changed: checksum mismatch, rejected");
    add(bad_key, "first key character changed: checksum mismatch, rejected");
    add(short_addr, "one character short: wrong length, rejected");
    add(bad_char, "'1' is outside the alphabet: rejected");
    add(addr + "_ABCDEFGH", "extra group: wrong length, rejected");
    j["address_decode_cases"] = cases;
    return j;
}

json section_identity(const Fixtures& f) {
    json j;
    j["verify"] =
        "ed25519_pub = RFC 8032 public key of seed; fingerprint = lowercase_hex(SHA-256('r2r-id-v1' || "
        "ed25519_pub)); contact_address = 'R2R_' + base32(pub || SHA3-256(pub || 'R2R')[0..3]) in groups of "
        "8 joined by '_'; decode every address_decode_cases input and compare accepted/pubkey_hex.";
    j["fingerprint_tag"] = "r2r-id-v1";
    j["fingerprint_construction"] = "lowercase_hex(SHA-256(\"r2r-id-v1\" || ed25519_pub)), 64 hex chars";
    j["address_checksum_construction"] = "SHA3-256(ed25519_pub || \"R2R\")[0..3] (FIPS 202 SHA3-256, not Keccak)";
    j["address_base32_alphabet"] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    j["address_construction"] =
        "raw = pub(32) || checksum(3) = 35 bytes = 280 bits = exactly 56 base32 characters, MSB first, no "
        "padding; output 'R2R' + ('_' + 8 chars) x 7";
    j["address_decoder"] =
        "drop '_', '-' and ' '; uppercase; strip a leading 'R2R'; require exactly 56 alphabet chars; "
        "decode; require SHA3-256(pub || 'R2R')[0..3] == bytes 32..34";
    j["identities"] = json::array({identity_entry("identity_a", f.seed_id_a, f.id_a),
                                   identity_entry("identity_b", f.seed_id_b, f.id_b),
                                   identity_entry("identity_c", f.seed_id_c, f.id_c)});
    j["identities"][2]["whitepaper_ref"] = "Appendix A.1 / A.10";

    check(f.id_c.ed_pub_b64() == kWpPubC_b64, "identity C public key vs white paper A.1");
    check(f.fp_c == kWpFpC, "identity C fingerprint vs white paper A.1");
    check(j["identities"][2]["address_checksum_hex"] == kWpChecksumC, "identity C checksum vs A.10");
    check(crypto::contact_address(f.id_c.ed_pub()) == kWpAddressC, "identity C address vs A.10");
    return j;
}

json node_entry(const std::string& label, const Bytes& seed, const crypto::NodeIdentity& n) {
    json j;
    j["label"] = label;
    j["seed_hex"] = hex(seed);
    j["ed25519_pub_hex"] = hex(n.ed_pub());
    j["ed25519_pub_b64"] = n.ed_pub_b64();
    j["node_id"] = n.node_id();
    j["node_id_preimage_hex"] = hex(cat({bytes_of("r2r-node-v1"), n.ed_pub()}));
    const Bytes x_priv = ossl_hkdf_sha256(seed, Bytes{}, "r2r-x25519-v1", 32);
    check(ossl_x25519_pub(x_priv) == n.x_pub(), "x25519 derivation reproduces NodeIdentity for " + label);
    j["x25519_priv_hex"] = hex(x_priv);
    j["x25519_pub_hex"] = hex(n.x_pub());
    j["x25519_pub_b64"] = n.x_pub_b64();
    check(crypto::node_id_from_ed_pub(n.ed_pub()) == n.node_id(), "node_id_from_ed_pub for " + label);
    return j;
}

json section_node_identity(const Fixtures& f) {
    json j;
    j["verify"] =
        "node_id = lowercase_hex(SHA-256('r2r-node-v1' || ed25519_pub))[0..32] (first 16 bytes); "
        "x25519_priv = HKDF-SHA256(ikm = seed, salt = empty, info = 'r2r-x25519-v1', L = 32); "
        "x25519_pub = X25519(x25519_priv, basepoint 9) with RFC 7748 clamping.";
    j["node_id_tag"] = "r2r-node-v1";
    j["node_id_construction"] = "lowercase_hex(SHA-256(\"r2r-node-v1\" || ed25519_pub)).substr(0, 32)";
    j["x25519_hkdf"] = {{"ikm", "the 32-byte seed"},
                        {"salt", "empty (RFC 5869: equivalent to 32 zero bytes)"},
                        {"info", "r2r-x25519-v1"},
                        {"hash", "SHA-256"},
                        {"length", 32},
                        {"note", "the x25519 private key is NOT the ed25519 key converted; it is an "
                                 "independent HKDF output of the same seed"}};
    j["ed25519"] = "private key = the seed itself (RFC 8032)";
    j["nodes"] = json::array({node_entry("relay_a", f.seed_relay_a, f.relay_a),
                              node_entry("relay_b", f.seed_relay_b, f.relay_b),
                              node_entry("relay_c", f.seed_relay_c, f.relay_c)});
    j["nodes"][0]["whitepaper_ref"] = "Appendix A.2";
    j["nodes"][1]["whitepaper_ref"] = "Appendix A.4b candidate 2";

    check(f.relay_a.ed_pub_b64() == kWpRelayAEd_b64, "relay A ed25519 vs A.2");
    check(f.relay_a.node_id() == kWpRelayANodeId, "relay A node_id vs A.2");
    check(j["nodes"][0]["x25519_priv_hex"] == kWpRelayAXPriv, "relay A x25519 private vs A.2");
    check(f.relay_a.x_pub_b64() == kWpRelayAX_b64, "relay A x25519 public vs A.2");
    check(f.relay_b.x_pub_b64() == kWpRelayBX_b64, "relay B x25519 public vs A.4b");
    return j;
}

json client_hello(const crypto::NodeIdentity& key, const std::string& id_field, std::int64_t ts,
                  const std::string& nonce) {
    json f{{"t", proto::kHello}, {"role", "client"}, {"proto", proto::kVersion}};
    f["id"] = id_field;
    f["pubkey"] = key.ed_pub_b64();
    f["ts"] = ts;
    f["nonce"] = nonce;
    f["sig"] = b64(sign(key, proto::client_auth_string(id_field, ts, nonce)));
    return f;
}

json section_signing(const Fixtures& f) {
    json j;
    j["verify"] =
        "Build each 'string' from its 'inputs' byte for byte (JSON-escaped here; '\\n' is 0x0a, no trailing "
        "newline), sign it with RFC 8032 Ed25519 under 'signer' seed and compare 'sig_b64' exactly "
        "(Ed25519 is deterministic); verify each hello frame as the relay would and compare 'expected'.";
    j["signer_seeds"] = {{"identity_a", hex(f.seed_id_a)},
                         {"identity_b", hex(f.seed_id_b)},
                         {"identity_c", hex(f.seed_id_c)},
                         {"relay_a", hex(f.seed_relay_a)}};

    // hello (relay handshake)
    {
        const std::string s = proto::hello_signing_string(f.relay_a.node_id(), kAdvertiseA, kTs, kNonce);
        const Bytes sig = sign(f.relay_a, s);
        j["hello_signing_string"] = {
            {"format", "\"r2r-hello-v1\\n\" || node_id || \"\\n\" || advertise || \"\\n\" || decimal(ts) || \"\\n\" || nonce"},
            {"inputs", {{"node_id", f.relay_a.node_id()}, {"advertise", kAdvertiseA}, {"ts", kTs}, {"nonce", kNonce}}},
            {"string", s},
            {"string_hex", hex(bytes_of(s))},
            {"signer", "relay_a"},
            {"sig_b64", b64(sig)},
            {"sig_hex", hex(sig)},
            {"whitepaper_ref", "Appendix A.3"},
            {"relay_hello_frame_fields",
             "t=hello role=relay proto=1 node_id advertise ed25519(b64 pub) x25519(b64 pub) tls ws_port wss_port "
             "ts nonce version sig; the receiving relay checks nonce length 16..64, |now-ts| <= window, "
             "node_id == node_id_from_ed_pub(ed25519) and the signature over this string"}};
        check(b64(sig) == kWpHelloSig, "hello signature vs A.3");
        check(crypto::verify_signature(f.relay_a.ed_pub(), s, sig), "hello signature verifies");
    }
    // client auth
    {
        const std::string s_a = proto::client_auth_string(f.fp_a, kTs, kNonce);
        const std::string s_c = proto::client_auth_string(f.fp_c, kTs, kNonce);
        const Bytes sig_a = sign(f.id_a, s_a);
        const Bytes sig_c = sign(f.id_c, s_c);
        j["client_auth_string"] = {
            {"format", "\"r2r-client-v1\\n\" || fingerprint || \"\\n\" || decimal(ts) || \"\\n\" || nonce"},
            {"cases", json::array({{{"inputs", {{"fingerprint", f.fp_a}, {"ts", kTs}, {"nonce", kNonce}}},
                                    {"string", s_a},
                                    {"string_hex", hex(bytes_of(s_a))},
                                    {"signer", "identity_a"},
                                    {"sig_b64", b64(sig_a)},
                                    {"sig_hex", hex(sig_a)}},
                                   {{"inputs", {{"fingerprint", f.fp_c}, {"ts", kTs}, {"nonce", kNonce}}},
                                    {"string", s_c},
                                    {"string_hex", hex(bytes_of(s_c))},
                                    {"signer", "identity_c"},
                                    {"sig_b64", b64(sig_c)},
                                    {"sig_hex", hex(sig_c)},
                                    {"whitepaper_ref", "Appendix A.1"}}})}};
        check(b64(sig_c) == kWpClientSigC, "client signature vs A.1");

        // X-R2R-Auth header: base64 of the compact proof JSON. Key order is
        // free for the relay; the white paper example uses this order.
        const std::string proof = "{\"id\":\"" + f.fp_c + "\",\"pubkey\":\"" + f.id_c.ed_pub_b64() +
                                  "\",\"ts\":" + std::to_string(kTs) + ",\"nonce\":\"" + kNonce +
                                  "\",\"sig\":\"" + b64(sig_c) + "\"}";
        const std::string header = util::b64_encode(proof);
        check(header == kWpAuthHeaderC, "X-R2R-Auth header vs A.1");
        j["x_r2r_auth_header"] = {{"proof_json", proof},
                                  {"header_value", header},
                                  {"note", "base64(compact JSON of the same proof object); decoded JSON <= 4096 bytes"},
                                  {"whitepaper_ref", "Appendix A.1"}};
    }
    // pointer
    {
        const std::string s = proto::pointer_signing_string(f.fp_c, kAdvertiseA, kTs);
        const Bytes sig = sign(f.relay_a, s);
        j["pointer_signing_string"] = {
            {"format", "\"r2r-pointer-v1\\n\" || fingerprint || \"\\n\" || address || \"\\n\" || decimal(ts)  (no nonce)"},
            {"inputs", {{"fingerprint", f.fp_c}, {"address", kAdvertiseA}, {"ts", kTs}}},
            {"string", s},
            {"string_hex", hex(bytes_of(s))},
            {"signer", "relay_a"},
            {"sig_b64", b64(sig)},
            {"sig_hex", hex(sig)},
            {"whitepaper_ref", "Appendix A.3"}};
        check(b64(sig) == kWpPointerSig, "pointer signature vs A.3");
    }
    // collect
    {
        const std::string s = proto::collect_signing_string(f.fp_c, kAdvertiseA, "collect-delete", kTs, kNonce);
        const Bytes sig = sign(f.id_c, s);
        j["collect_signing_string"] = {
            {"format", "\"r2r-collect-v1\\n\" || fingerprint || \"\\n\" || holder || \"\\n\" || scope || \"\\n\" || decimal(ts) || \"\\n\" || nonce"},
            {"inputs", {{"fingerprint", f.fp_c}, {"holder", kAdvertiseA}, {"scope", "collect-delete"}, {"ts", kTs}, {"nonce", kNonce}}},
            {"string", s},
            {"string_hex", hex(bytes_of(s))},
            {"signer", "identity_c"},
            {"sig_b64", b64(sig)},
            {"sig_hex", hex(sig)},
            {"whitepaper_ref", "Appendix A.3"}};
        check(b64(sig) == kWpCollectSig, "collect signature vs A.3");
    }
    // hello frames
    {
        json frames = json::array();
        auto add = [&](json frame, const char* name, const char* expected, const char* why) {
            const std::string verdict = client_proof_verdict(frame);
            check(verdict == expected, std::string("hello frame '") + name + "' verdict " + verdict);
            frames.push_back({{"name", name}, {"frame", frame}, {"expected", expected}, {"why", why}});
        };
        add(client_hello(f.id_a, f.fp_a, kTs, kNonce), "accept", "accept",
            "fingerprint(pubkey) == id and the signature over client_auth_string(id, ts, nonce) verifies");
        add(client_hello(f.id_a, f.fp_b, kTs, kNonce), "reject_fingerprint_mismatch", proto::kErrNotAuthorised,
            "id is identity_b's fingerprint but pubkey/sig belong to identity_a: the signature itself is valid "
            "for the string, yet fingerprint(pubkey) != id, so the relay must refuse");
        {
            json bad = client_hello(f.id_a, f.fp_a, kTs, kNonce);
            Bytes sig = *util::b64_decode(bad["sig"].get<std::string>());
            sig[0] ^= 0xff;
            bad["sig"] = b64(sig);
            add(bad, "reject_bad_signature", proto::kErrNotAuthorised, "first signature byte flipped");
        }
        {
            json bad = client_hello(f.id_a, f.fp_a, kTs, kNonce);
            bad["nonce"] = "short";
            bad["sig"] = b64(sign(f.id_a, proto::client_auth_string(f.fp_a, kTs, "short")));
            add(bad, "reject_short_nonce", proto::kErrNotAuthorised, "nonce must be 16..64 characters");
        }
        {
            json bad = client_hello(f.id_a, "not-a-fingerprint", kTs, kNonce);
            add(bad, "reject_malformed_id", proto::kErrBadField, "id is not 32..128 lowercase hex");
        }
        j["hello_frames"] = {
            {"note", "ts is fixed here for determinism. A live relay additionally requires |now - ts| <= 600 s, so "
                     "to test against a running relay substitute the current time and re-sign. The relay trims "
                     "and lowercases 'id' before every check; 'ts' must be a JSON integer."},
            {"relay_checks_in_order",
             json::array({"id (trimmed, lowercased) is a valid fingerprint, else bad_field",
                          "pubkey and sig present, nonce length 16..64, else not_authorised",
                          "|now - ts| <= 600, else not_authorised",
                          "pubkey decodes to 32 bytes and sig decodes, else not_authorised",
                          "fingerprint(pubkey) == id, else not_authorised",
                          "Ed25519 verify(pubkey, client_auth_string(id, ts, nonce), sig), else not_authorised"})},
            {"frames", frames}};
    }
    return j;
}

json section_ed25519_verify(const Fixtures& f) {
    const std::string msg = "The quick brown fox jumps over the lazy dog";
    const std::string tampered = "The quick brown fox jumps over the lazy cog";
    const Bytes sig = sign(f.id_a, msg);
    check(crypto::verify_signature(f.id_a.ed_pub(), msg, sig), "verify true");
    check(!crypto::verify_signature(f.id_a.ed_pub(), tampered, sig), "verify tampered false");
    check(!crypto::verify_signature(f.id_b.ed_pub(), msg, sig), "verify wrong key false");
    json j;
    j["verify"] = "Ed25519_Verify(pubkey, message, sig) must give 'expected' for each case.";
    j["signature_encoding"] = "64 raw bytes (R || S), base64 on the wire";
    j["cases"] = json::array(
        {{{"pubkey_hex", hex(f.id_a.ed_pub())}, {"message", msg}, {"sig_hex", hex(sig)}, {"sig_b64", b64(sig)}, {"expected", true},
          {"note", "signed by identity_a"}},
         {{"pubkey_hex", hex(f.id_a.ed_pub())}, {"message", tampered}, {"sig_hex", hex(sig)}, {"sig_b64", b64(sig)}, {"expected", false},
          {"note", "message tampered (dog -> cog)"}},
         {{"pubkey_hex", hex(f.id_b.ed_pub())}, {"message", msg}, {"sig_hex", hex(sig)}, {"sig_b64", b64(sig)}, {"expected", false},
          {"note", "wrong public key (identity_b)"}}});
    return j;
}

json turn_vector(const std::string& secret, std::int64_t now, std::int64_t ttl, const std::string& identity) {
    json j;
    j["inputs"] = {{"secret", secret}, {"now", now}, {"ttl_seconds", ttl}, {"identity", identity}};
    std::string username = std::to_string(now + ttl);
    j["expiry"] = now + ttl;
    if (!identity.empty()) {
        const std::string material = "turn-handle|" + std::to_string(now / 86400) + "|" + identity;
        const Bytes mac = crypto::hmac_sha256(secret, material);
        j["day"] = now / 86400;
        j["handle_material"] = material;
        j["handle_hmac_sha256_hex"] = hex(mac);
        j["handle"] = hex(mac).substr(0, 12);
        username += ":" + hex(mac).substr(0, 12);
    }
    const Bytes mac1 = crypto::hmac_sha1(secret, username);
    j["username"] = username;
    j["credential_hmac_sha1_hex"] = hex(mac1);
    j["credential"] = b64(mac1);
    return j;
}

json section_hmac_and_turn(const Fixtures& f) {
    json j;
    j["verify"] =
        "HMAC per RFC 2104 over the UTF-8 bytes of key and message; TURN: username = decimal(now + ttl) [':' + "
        "first 12 hex chars of HMAC-SHA256(secret, 'turn-handle|' + decimal(now div 86400) + '|' + identity)], "
        "credential = base64(HMAC-SHA1(secret, username)).";
    const std::string fox = "The quick brown fox jumps over the lazy dog";
    j["hmac_cases"] = json::array(
        {{{"key", "key"}, {"message", fox}, {"hmac_sha1_hex", hex(crypto::hmac_sha1("key", fox))},
          {"hmac_sha256_hex", hex(crypto::hmac_sha256("key", fox))}, {"note", "well-known RFC 2104 style check"}},
         {{"key", ""}, {"message", ""}, {"hmac_sha1_hex", hex(crypto::hmac_sha1("", ""))},
          {"hmac_sha256_hex", hex(crypto::hmac_sha256("", ""))}, {"note", "empty key and message"}},
         {{"key", kTurnSecret}, {"message", "1754331600"}, {"hmac_sha1_hex", hex(crypto::hmac_sha1(kTurnSecret, "1754331600"))},
          {"hmac_sha256_hex", hex(crypto::hmac_sha256(kTurnSecret, "1754331600"))}, {"note", "TURN secret over a bare expiry"}}});
    check(hex(crypto::hmac_sha1("key", fox)) == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9", "HMAC-SHA1 known answer");
    check(hex(crypto::hmac_sha256("key", fox)) == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
          "HMAC-SHA256 known answer");

    j["turn_rest_credentials"] = {
        {"construction",
         "expiry = now + ttl; handle = hex(HMAC-SHA256(secret, \"turn-handle|\" + decimal(now / 86400) + \"|\" + "
         "identity))[0..12]; username = decimal(expiry) + \":\" + handle (no handle part when identity is empty); "
         "credential = base64(HMAC-SHA1(secret, username))"},
        {"note", "the day counter uses integer division of Unix seconds by 86400; the handle is the first 12 lowercase "
                 "hex characters (6 bytes) of the full 32-byte HMAC-SHA256"},
        {"cases", json::array({turn_vector(kTurnSecret, kTs, kTurnTtl, f.fp_c), turn_vector(kTurnSecret, kTs, kTurnTtl, f.fp_a),
                               turn_vector(kTurnSecret, kTs, kTurnTtl, "")})}};
    j["turn_rest_credentials"]["cases"][0]["whitepaper_ref"] = "Appendix A.7";
    j["turn_rest_credentials"]["cases"][2]["note"] = "anonymous session: no identity, so no ':handle' suffix";
    check(j["turn_rest_credentials"]["cases"][0]["username"] == kWpTurnUsername, "TURN username vs A.7");
    check(j["turn_rest_credentials"]["cases"][0]["credential"] == kWpTurnCredential, "TURN credential vs A.7");
    return j;
}

json section_sealed_box(const Fixtures& f, const Bytes& lib_blob) {
    json j;
    j["verify"] =
        "Open 'blob' with relay_a's x25519 private key following 'layout' and 'kdf' and compare 'plaintext'; for "
        "'deterministic', rebuild the blob from eph_priv and nonce and compare it byte for byte; every 'negative' "
        "case must fail to open.";
    j["layout"] = "version(1)=0x01 || eph_pub(32) || nonce(12) || ciphertext || tag(16); overhead 61 bytes";
    j["kdf"] = {{"shared", "X25519(eph_priv, recipient_x25519_pub); an all-zero result MUST be rejected"},
                {"hkdf", "HKDF-SHA256(ikm = shared, salt = eph_pub || recipient_x25519_pub (64 bytes), info = "
                         "\"r2r-seal-v1\", L = 32)"},
                {"cipher", "AES-256-GCM, 12-byte nonce, 16-byte tag appended to the ciphertext"},
                {"aad", "0x01 || eph_pub || recipient_x25519_pub (65 bytes): the version byte and both public keys"},
                {"note", "the recipient's own public key is bound into both the HKDF salt and the AAD, so a blob "
                         "sealed to one relay cannot be opened by, or re-targeted to, another"}};

    // Deterministic reconstruction (white paper A.4).
    {
        const Bytes eph_priv(32, 0x42);
        const Bytes nonce = bytes_of("defghijklmno");
        const Bytes pt = bytes_of(kWpSealPlain);
        const SealTrace t = seal_fixed(f.relay_a.x_pub(), eph_priv, nonce, pt);
        check(hex(t.eph_pub) == kWpSealEphPub, "A.4 eph_pub");
        check(hex(t.shared) == kWpSealShared, "A.4 shared secret");
        check(hex(t.key) == kWpSealKey, "A.4 HKDF key");
        check(b64(t.blob) == kWpSealBlob_b64, "A.4 sealed blob");
        auto opened = f.relay_a.unseal(t.blob);
        check(opened && *opened == pt, "A.4 blob opens with relay A");
        check(!f.relay_b.unseal(t.blob), "A.4 blob does not open with relay B");
        j["deterministic"] = {{"whitepaper_ref", "Appendix A.4"},
                              {"recipient", "relay_a"},
                              {"recipient_x25519_pub_hex", hex(f.relay_a.x_pub())},
                              {"eph_priv_hex", hex(eph_priv)},
                              {"eph_pub_hex", hex(t.eph_pub)},
                              {"nonce_hex", hex(nonce)},
                              {"plaintext", kWpSealPlain},
                              {"plaintext_hex", hex(pt)},
                              {"x25519_shared_hex", hex(t.shared)},
                              {"hkdf_salt_hex", hex(t.salt)},
                              {"hkdf_info", "r2r-seal-v1"},
                              {"aes_key_hex", hex(t.key)},
                              {"aad_hex", hex(t.aad)},
                              {"ciphertext_hex", hex(slice(t.ct_tag, 0, t.ct_tag.size() - 16))},
                              {"tag_hex", hex(slice(t.ct_tag, t.ct_tag.size() - 16, 16))},
                              {"blob_hex", hex(t.blob)},
                              {"blob_b64", b64(t.blob)},
                              {"opens_with", json::array({"relay_a"})},
                              {"fails_with", json::array({"relay_b"})}};
    }
    // Library-generated blob, embedded once.
    {
        const Bytes pt = bytes_of(kSealPlain);
        auto opened = f.relay_a.unseal(lib_blob);
        check(opened && *opened == pt, "embedded sealed blob opens with relay A");
        check(!f.relay_b.unseal(lib_blob), "embedded sealed blob does not open with relay B");
        check(!f.relay_c.unseal(lib_blob), "embedded sealed blob does not open with relay C");
        check(lib_blob.size() == crypto::kSealOverhead + pt.size(), "sealed blob length");
        Bytes tampered = lib_blob;
        tampered[1 + 32 + 12] ^= 0x01;
        Bytes bad_version = lib_blob;
        bad_version[0] = 0x02;
        Bytes bad_tag = lib_blob;
        bad_tag.back() ^= 0x01;
        check(!f.relay_a.unseal(tampered) && !f.relay_a.unseal(bad_version) && !f.relay_a.unseal(bad_tag),
              "tampered sealed blobs fail");
        j["library_generated"] = {
            {"generated_by", "crypto::seal(relay_a.x_pub, plaintext) with a random ephemeral key and nonce, run once"},
            {"recipient", "relay_a"},
            {"recipient_x25519_pub_hex", hex(f.relay_a.x_pub())},
            {"plaintext", kSealPlain},
            {"plaintext_hex", hex(pt)},
            {"blob_hex", hex(lib_blob)},
            {"blob_b64", b64(lib_blob)},
            {"blob_len", lib_blob.size()},
            {"parsed", {{"version", lib_blob[0]},
                        {"eph_pub_hex", hex(slice(lib_blob, 1, 32))},
                        {"nonce_hex", hex(slice(lib_blob, 33, 12))},
                        {"ciphertext_hex", hex(slice(lib_blob, 45, lib_blob.size() - 45 - 16))},
                        {"tag_hex", hex(slice(lib_blob, lib_blob.size() - 16, 16))}}},
            {"opens_with", json::array({"relay_a"})},
            {"negative", json::array({{{"case", "opened by relay_b"}, {"opens", false}},
                                      {{"case", "opened by relay_c"}, {"opens", false}},
                                      {{"case", "first ciphertext byte flipped"}, {"opens", false}},
                                      {{"case", "version byte set to 0x02"}, {"opens", false}},
                                      {{"case", "last tag byte flipped"}, {"opens", false}}})}};
    }
    return j;
}

json section_multi(const Fixtures& f, const Bytes& blob) {
    json j;
    j["verify"] =
        "For each slot i, try unseal(slot_i) with your x25519 key; a 32-byte result is the layer key K; then "
        "AES-256-GCM-decrypt(K, nonce, ciphertext||tag, aad = header) and compare 'plaintext'. relay_c must fail on "
        "every slot; swapped slots must fail the tag for everyone.";
    j["layout"] =
        "0x02 || n(1) || n x slot(93) || nonce(12) || ciphertext || tag(16); slot_i = seal(candidate_i.x25519_pub, K) "
        "where K is a fresh 32-byte layer key (61 + 32 = 93 bytes); 1 <= n <= 3; minimum total 123 bytes";
    j["aad"] = "the header: 0x02 || n || all n slots (2 + 93n bytes)";
    j["cipher"] = "AES-256-GCM under K with a fresh 12-byte nonce";
    j["note"] =
        "nothing says which slot belongs to which relay; an opener tries every slot in order and uses the first that "
        "unseals to exactly 32 bytes";

    const Bytes pt = bytes_of(kMultiPlain);
    check(blob.size() >= crypto::kMultiMin && blob[0] == crypto::kMultiVersion && blob[1] == 2, "multi blob header");
    const std::size_t header = 2 + 2 * crypto::kSlotLen;
    auto a = f.relay_a.unseal_multi(blob);
    auto b = f.relay_b.unseal_multi(blob);
    check(a && *a == pt, "multi blob opens with relay A");
    check(b && *b == pt, "multi blob opens with relay B");
    check(!f.relay_c.unseal_multi(blob), "multi blob does not open with relay C");
    Bytes swapped = blob;
    for (std::size_t i = 0; i < crypto::kSlotLen; ++i)
        std::swap(swapped[2 + i], swapped[2 + crypto::kSlotLen + i]);
    check(!f.relay_a.unseal_multi(swapped) && !f.relay_b.unseal_multi(swapped), "swapped slots fail the tag");
    Bytes stripped = blob;
    stripped[1] = 1;
    stripped.erase(stripped.begin() + 2 + static_cast<std::ptrdiff_t>(crypto::kSlotLen),
                   stripped.begin() + 2 + static_cast<std::ptrdiff_t>(2 * crypto::kSlotLen));
    check(!f.relay_a.unseal_multi(stripped), "stripped slot fails the tag");
    j["embedded"] = {
        {"generated_by", "crypto::seal_multi({relay_a.x_pub, relay_b.x_pub}, plaintext), run once"},
        {"recipients", json::array({{{"label", "relay_a"}, {"x25519_pub_b64", f.relay_a.x_pub_b64()}},
                                    {{"label", "relay_b"}, {"x25519_pub_b64", f.relay_b.x_pub_b64()}}})},
        {"plaintext", kMultiPlain},
        {"plaintext_hex", hex(pt)},
        {"blob_hex", hex(blob)},
        {"blob_b64", b64(blob)},
        {"blob_len", blob.size()},
        {"parsed", {{"version", blob[0]},
                    {"n", blob[1]},
                    {"slots_hex", json::array({hex(slice(blob, 2, crypto::kSlotLen)),
                                               hex(slice(blob, 2 + crypto::kSlotLen, crypto::kSlotLen))})},
                    {"aad_hex", hex(slice(blob, 0, header))},
                    {"nonce_hex", hex(slice(blob, header, 12))},
                    {"ciphertext_hex", hex(slice(blob, header + 12, blob.size() - header - 12 - 16))},
                    {"tag_hex", hex(slice(blob, blob.size() - 16, 16))}}},
        {"opens_with", json::array({"relay_a", "relay_b"})},
        {"negative", json::array({{{"case", "opened by relay_c (unrelated seed)"}, {"opens", false}},
                                  {{"case", "slot 1 and slot 2 swapped"}, {"opens", false}},
                                  {{"case", "n set to 1 and slot 2 removed"}, {"opens", false}}})}};

    // White paper A.4b: a layer produced by the wallet's JavaScript.
    {
        const Bytes layer = *util::b64_decode(kWpLayer_b64);
        const Bytes expect = hx(kWpLayerPlainHex);
        auto pa = f.relay_a.unseal_multi(layer);
        auto pb = f.relay_b.unseal_multi(layer);
        check(pa && *pa == expect, "A.4b layer opens with relay A");
        check(pb && *pb == expect, "A.4b layer opens with relay B");
        check(!f.relay_c.unseal_multi(layer), "A.4b layer does not open with relay C");
        auto parsed = onion::parse(*pa, kMaxBody);
        check(parsed && parsed->terminal && parsed->deliver.to == f.fp_c && parsed->deliver.home == kAdvertiseA &&
                  parsed->deliver.msg_id == kMsgId && str_of(parsed->deliver.body) == "hello",
              "A.4b layer parses as the expected terminal");
        j["whitepaper_a4b"] = {{"whitepaper_ref", "Appendix A.4b"},
                               {"note", "sealed by the reference wallet (JavaScript) with fixed K, nonces and ephemeral keys "
                                        "listed in the white paper; both candidates open it with libr2r_core"},
                               {"layer_b64", kWpLayer_b64},
                               {"layer_hex", hex(layer)},
                               {"plaintext_hex", hex(expect)},
                               {"opens_with", json::array({"relay_a", "relay_b"})},
                               {"parsed_terminal", {{"to", parsed->deliver.to}, {"home", parsed->deliver.home},
                                                    {"msg_id", parsed->deliver.msg_id}, {"body_utf8", "hello"}}}};
    }
    return j;
}

json hop_json(const std::string& label, const std::string& address, const crypto::NodeIdentity& n) {
    return json{{"relay", label}, {"address", address}, {"x25519_b64", n.x_pub_b64()}};
}

json peel_routing(const crypto::NodeIdentity& who, const std::string& label, const Bytes& blob) {
    auto pt = who.unseal_multi(blob);
    check(pt.has_value(), label + " opens its onion layer");
    auto layer = onion::parse(*pt, kMaxBody);
    check(layer && !layer->terminal, label + " layer is a routing layer");
    const std::size_t header = pt->size() - layer->inner.size();
    json j;
    j["opened_by"] = label;
    j["layer_plaintext_hex"] = hex(*pt);
    j["kind"] = "routing";
    j["type_byte"] = (*pt)[0];
    j["n"] = (*pt)[1];
    j["routing_header_hex"] = hex(slice(*pt, 0, header));
    j["next"] = layer->next;
    j["inner_blob_hex"] = hex(layer->inner);
    j["inner_blob_b64"] = b64(layer->inner);
    j["inner_blob_len"] = layer->inner.size();
    j["forwards_frame"] = {{"t", proto::kOnion}, {"blob", b64(layer->inner)}, {"hops", 7}};
    j["forwards_to"] = "the first 'next' candidate with a live link, else dialled in order; itself is skipped";
    return j;
}

json peel_terminal(const crypto::NodeIdentity& who, const std::string& label, const Bytes& blob) {
    auto pt = who.unseal_multi(blob);
    check(pt.has_value(), label + " opens the terminal layer");
    auto layer = onion::parse(*pt, kMaxBody);
    check(layer && layer->terminal, label + " layer is a terminal layer");
    const std::size_t mlen = (static_cast<std::size_t>((*pt)[1]) << 8) | (*pt)[2];
    json j;
    j["opened_by"] = label;
    j["layer_plaintext_hex"] = hex(*pt);
    j["kind"] = "terminal";
    j["type_byte"] = (*pt)[0];
    j["meta_len"] = mlen;
    j["meta_json"] = str_of(slice(*pt, 3, mlen));
    j["to"] = layer->deliver.to;
    j["home"] = layer->deliver.home;
    j["msg_id"] = layer->deliver.msg_id;
    j["hint"] = layer->deliver.from_hint;
    j["body_hex"] = hex(layer->deliver.body);
    j["body_utf8"] = str_of(layer->deliver.body);
    return j;
}

json section_onion(const Fixtures& f, const Bytes& blob1, const Bytes& blob2) {
    json j;
    j["verify"] =
        "Open 'blob' with relay_a (multi-recipient layer), parse the routing plaintext, forward 'inner_blob' to a "
        "'next' candidate, open it there and parse the terminal record; compare every field. A port that builds "
        "routes should produce blobs that these relays peel to the same plaintexts (the blobs themselves differ "
        "because sealing is randomised).";
    j["layer"] = "each layer is a multi-recipient sealed box (see multi_recipient_layer) sealed to the 1..3 candidates of "
                 "one route position; the outermost layer is what the client sends";
    j["routing_plaintext"] =
        "0x01 || n(1) || n x ( len8 || \"host:port\" ) || inner layer bytes; addresses are the sender's text and are "
        "canonicalised by the relay with parse_address(default port 8787); the inner layer must be >= 123 bytes";
    j["terminal_plaintext"] =
        "0x02 || len16be(2) || meta JSON (UTF-8) || body; meta = {\"to\":\"<fp>[@<home relay>]\",\"id\":\"<uuid4>\","
        "\"hint\"?:\"<=128 chars\"}; body is 1..max_payload bytes of end-to-end ciphertext; the reference builder emits "
        "meta keys in alphabetical order (hint, id, to) but any order parses";
    j["client_frame"] = "{\"t\":\"onion\",\"blob\":\"<base64 outer layer>\"} sent with NO hello; success is silent";
    j["build_order"] = "seal the terminal plaintext to the last position; then for each earlier position, from last to "
                       "first: plaintext = routing header naming the NEXT position's candidates || the layer just built, "
                       "sealed to this position's candidates";

    const json terminal_inputs = {{"to", f.fp_a},        {"home", kAdvertiseB},   {"msg_id", kMsgId},
                                  {"hint", kOnionHint},  {"body_utf8", kOnionBody}, {"body_hex", hex(bytes_of(kOnionBody))},
                                  {"meta_to_field", f.fp_a + "@" + kAdvertiseB}};

    // Route 1: A then B.
    {
        json hop_a = peel_routing(f.relay_a, "relay_a", blob1);
        check(hop_a["next"] == json::array({kAdvertiseB}), "route 1: hop A learns B");
        const Bytes inner = hx(hop_a["inner_blob_hex"].get<std::string>());
        json hop_b = peel_terminal(f.relay_b, "relay_b", inner);
        check(hop_b["to"] == f.fp_a && hop_b["home"] == kAdvertiseB && hop_b["msg_id"] == kMsgId &&
                  hop_b["hint"] == kOnionHint && hop_b["body_utf8"] == kOnionBody,
              "route 1: hop B terminal fields");
        check(!f.relay_b.unseal_multi(blob1) && !f.relay_c.unseal_multi(blob1), "route 1: only A opens the outer layer");
        check(!f.relay_a.unseal_multi(inner) && !f.relay_c.unseal_multi(inner), "route 1: only B opens the inner layer");
        j["route_a_then_b"] = {
            {"generated_by", "onion::build({{relay_a}, {relay_b}}, terminal), run once"},
            {"positions", json::array({json::array({hop_json("relay_a", kAdvertiseA, f.relay_a)}),
                                       json::array({hop_json("relay_b", kAdvertiseB, f.relay_b)})})},
            {"terminal", terminal_inputs},
            {"blob_hex", hex(blob1)},
            {"blob_b64", b64(blob1)},
            {"blob_len", blob1.size()},
            {"client_frame", {{"t", proto::kOnion}, {"blob", b64(blob1)}}},
            {"hop_a", hop_a},
            {"hop_b", hop_b},
            {"negative", json::array({{{"case", "relay_b opens the outer blob"}, {"opens", false}},
                                      {{"case", "relay_c opens the outer blob"}, {"opens", false}},
                                      {{"case", "relay_a opens the inner blob"}, {"opens", false}},
                                      {{"case", "relay_c opens the inner blob"}, {"opens", false}}})}};
    }
    // Route 2: A then {B or C}.
    {
        json hop_a = peel_routing(f.relay_a, "relay_a", blob2);
        check(hop_a["next"] == json::array({kAdvertiseB, kAdvertiseC}), "route 2: hop A learns B and C");
        const Bytes inner = hx(hop_a["inner_blob_hex"].get<std::string>());
        json hop_b = peel_terminal(f.relay_b, "relay_b", inner);
        json hop_c = peel_terminal(f.relay_c, "relay_c", inner);
        check(hop_b["layer_plaintext_hex"] == hop_c["layer_plaintext_hex"], "route 2: B and C see the same plaintext");
        check(hop_b["to"] == f.fp_a && hop_b["home"] == kAdvertiseB, "route 2: terminal fields");
        check(!f.relay_a.unseal_multi(inner), "route 2: A cannot open the inner layer");
        j["route_a_then_b_or_c"] = {
            {"generated_by", "onion::build({{relay_a}, {relay_b, relay_c}}, terminal), run once"},
            {"positions", json::array({json::array({hop_json("relay_a", kAdvertiseA, f.relay_a)}),
                                       json::array({hop_json("relay_b", kAdvertiseB, f.relay_b),
                                                    hop_json("relay_c", kAdvertiseC, f.relay_c)})})},
            {"terminal", terminal_inputs},
            {"blob_hex", hex(blob2)},
            {"blob_b64", b64(blob2)},
            {"blob_len", blob2.size()},
            {"hop_a", hop_a},
            {"hop_b", hop_b},
            {"hop_c_standby", hop_c},
            {"note", "relay_c is a standby terminal: it opens the same layer and, because 'home' names relay_b, forwards "
                     "the payload there as an ordinary send; relay_b stores it"}};
    }
    return j;
}

json section_addressing(const Fixtures& f) {
    json j;
    j["verify"] = "parse_target(input) must give {valid, fingerprint, relay}; parse_address(input, 8787) must give "
                  "{valid, canonical}.";
    j["rules"] = {{"split", "at the first '@'; the left part is trimmed and lowercased and must be 32..128 hex chars"},
                  {"relay", "trimmed; 'ws://' (default port 8787) or 'wss://' (default port 8788) prefix is stripped "
                            "case-insensitively; the rest goes through parse_address"},
                  {"parse_address", "rejects >300 bytes, bytes <= 0x20 or >= 0x7f and any of / \\ @ ? # , ; '[v6]:port', a "
                                    "bare string with 2+ ':' is IPv6 with the default port, else host[:port]; port 1..65535; "
                                    "host lowercased; output host:port or [v6]:port"},
                  {"length", "the whole target must be 1..400 bytes"},
                  {"trailing_slash", "NOT stripped by parse_target: 'fp@wss://host/' is invalid (see cases)"}};
    const std::string fp = f.fp_a;
    const std::string FP = [&] { std::string u = fp; for (auto& c : u) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c))); return u; }();
    json cases = json::array();
    auto add = [&](const std::string& in, const char* note) {
        auto t = proto::parse_target(in);
        cases.push_back({{"input", in}, {"valid", t.valid}, {"fingerprint", t.fingerprint}, {"relay", t.relay}, {"note", note}});
    };
    add(fp, "bare fingerprint");
    add(fp + "@203.0.113.10:8787", "fp@host:port");
    add(fp + "@203.0.113.10", "fp@host: default port 8787");
    add(fp + "@ws://relay.example", "ws:// scheme: default port 8787");
    add(fp + "@wss://relay.example", "wss:// scheme: default port 8788");
    add(fp + "@WSS://Relay.Example:9000", "scheme and host are case-insensitive; host lowercased");
    add(FP, "uppercase fingerprint is normalised to lowercase");
    add("  " + fp + "  ", "surrounding whitespace is trimmed");
    add(fp + "@[2001:db8::1]:8787", "bracketed IPv6 literal");
    add(fp + "@2001:db8::1", "bare IPv6 literal gets the default port and brackets");
    add(std::string(64, 'z'), "not hex: invalid");
    add(fp + "@", "empty relay after '@': invalid");
    add(fp + "@wss://relay.example/", "trailing slash: invalid (parse_address rejects '/')");
    add(fp + "@relay.example:8787/r2r", "path: invalid");
    add(fp + "@relay.example:99999", "port out of range: invalid");
    add(fp + "@" + std::string(340, 'a'), "total length > 400: invalid");
    add(fp.substr(0, 31), "31 hex chars: invalid");
    add(fp.substr(0, 32), "32 hex chars: valid (minimum)");
    add(fp + fp, "128 hex chars: valid (maximum)");
    add(fp + fp + "a", "129 hex chars: invalid");
    add("", "empty: invalid");
    j["parse_target_cases"] = cases;

    json acases = json::array();
    auto add_addr = [&](const std::string& in, const char* note) {
        auto a = util::parse_address(in, 8787);
        acases.push_back({{"input", in}, {"default_port", 8787}, {"valid", a.has_value()},
                          {"canonical", a ? json(a->str()) : json(nullptr)}, {"note", note}});
    };
    add_addr("Relay.Example", "host lowercased, default port");
    add_addr("relay.example:65535", "maximum port");
    add_addr("relay.example:0", "port 0: invalid");
    add_addr("[::1]", "bracketed IPv6 without port");
    add_addr("::1", "bare IPv6");
    add_addr("wss://relay.example", "schemes are rejected by parse_address itself (parse_target strips them first)");
    add_addr("-relay.example", "host may not start with '-'");
    add_addr("relay..example", "'..' in host: invalid");
    j["parse_address_cases"] = acases;
    return j;
}

json section_invites_and_fingerprints(const Fixtures& f) {
    json j;
    j["verify"] = "invite codes are random: check only the regexes and the fixed-entropy example; compare "
                  "normalize/hint/is_valid_fingerprint/is_uuid_v4 outputs.";
    const std::string crock = "[0-9ABCDEFGHJKMNPQRSTVWXYZ]{4}";
    const std::string re_plain = "^R2R-" + crock + "-" + crock + "-" + crock + "$";
    const std::string re_hinted = "^R2R-[0-9A-F]{4}-[0-9A-F]{4}-" + crock + "-" + crock + "-" + crock + "$";
    const std::regex rp(re_plain), rh(re_hinted);
    int checked = 0;
    for (int i = 0; i < 32; ++i) {
        check(std::regex_match(crypto::invite_code(), rp), "plain invite code matches its regex");
        check(std::regex_match(crypto::invite_code("5C7193E9"), rh), "hinted invite code matches its regex");
        checked += 2;
    }
    j["invite_code"] = {
        {"alphabet", "0123456789ABCDEFGHJKMNPQRSTVWXYZ (Crockford base32: no I, L, O, U)"},
        {"format_plain", "R2R-XXXX-XXXX-XXXX"},
        {"format_hinted", "R2R-HHHH-HHHH-XXXX-XXXX-XXXX (HHHHHHHH = 8 uppercase hex chars of an IPv4 routing hint)"},
        {"regex_plain", re_plain},
        {"regex_hinted", re_hinted},
        {"entropy", "8 random bytes read as a big-endian uint64 v; character i (0..11) = alphabet[(v >> (55 - 5*i)) & 31]; "
                    "the low 4 bits of v are unused (60 bits of entropy)"},
        {"random_samples_checked", checked},
        {"all_samples_matched", true},
        {"fixed_entropy_example", {{"entropy_hex", "0123456789abcdef"},
                                   {"hint_ipv4", "92.113.147.233"},
                                   {"hint_hex", util::ipv4_hint_hex("92.113.147.233")},
                                   {"plain_code", crockford_code(hx("0123456789abcdef"), "")},
                                   {"hinted_code", crockford_code(hx("0123456789abcdef"), util::ipv4_hint_hex("92.113.147.233"))},
                                   {"note", "computed by re-implementing the encoding above (the library only draws random entropy); "
                                            "normalize_invite_code returns both unchanged"},
                                   {"whitepaper_ref", "Appendix A.5"}}}};
    check(util::ipv4_hint_hex("92.113.147.233") == "5C7193E9", "ipv4 hint vs A.5");
    check(crockford_code(hx("0123456789abcdef"), "") == "R2R-28T5-CY4T-QKFF", "plain code vs A.5");
    check(crockford_code(hx("0123456789abcdef"), "5C7193E9") == "R2R-5C71-93E9-28T5-CY4T-QKFF", "hinted code vs A.5");
    check(util::normalize_invite_code("R2R-28T5-CY4T-QKFF") == "R2R-28T5-CY4T-QKFF", "normalize identity");

    json norm = json::array();
    auto add_norm = [&](const std::string& in, const char* note) {
        norm.push_back({{"input", in}, {"canonical", util::normalize_invite_code(in)}, {"note", note}});
    };
    add_norm("r2r-5c71-93e9-28t5-cy4t-qkff", "lowercase hinted code -> uppercase");
    add_norm("R2R-28T5-CY4T-QKFO", "O folds to 0");
    add_norm("R2R-28T5-CY4T-QKFI", "I folds to 1");
    add_norm("R2R-28T5-CY4T-QKFL", "L folds to 1");
    add_norm("R2R-28T5-CY4T-QKFU", "U is not Crockford: invalid (empty)");
    add_norm(" R2R-28T5-CY4T-QKFF ", "surrounding whitespace trimmed");
    add_norm("R2R-28T5-CY4T", "too few groups: invalid");
    add_norm("3B241101-E2BB-4255-8CAF-4136C566A962", "legacy UUID v4 code -> lowercase");
    add_norm("3b241101-e2bb-1255-8caf-4136c566a962", "legacy code that is not a v4 UUID: invalid");
    j["normalize_invite_code_cases"] = norm;
    check(norm[0]["canonical"] == "R2R-5C71-93E9-28T5-CY4T-QKFF" && norm[1]["canonical"] == "R2R-28T5-CY4T-QKF0" &&
              norm[4]["canonical"] == "",
          "normalize cases vs A.5");
    j["invite_hint_ip_cases"] = json::array({{{"input", "R2R-5C71-93E9-28T5-CY4T-QKFF"}, {"ip", util::invite_hint_ip("R2R-5C71-93E9-28T5-CY4T-QKFF")}},
                                             {{"input", "R2R-28T5-CY4T-QKFF"}, {"ip", util::invite_hint_ip("R2R-28T5-CY4T-QKFF")}}});
    j["ipv4_hint_hex_cases"] = json::array({{{"input", "92.113.147.233"}, {"hex", util::ipv4_hint_hex("92.113.147.233")}},
                                            {{"input", "203.0.113.10"}, {"hex", util::ipv4_hint_hex("203.0.113.10")}},
                                            {{"input", "relay.example"}, {"hex", util::ipv4_hint_hex("relay.example")}},
                                            {{"input", "256.1.1.1"}, {"hex", util::ipv4_hint_hex("256.1.1.1")}}});

    json fps = json::array();
    auto add_fp = [&](const std::string& in, const char* note) {
        fps.push_back({{"input", in}, {"valid", util::is_valid_fingerprint(in)}, {"note", note}});
    };
    add_fp(f.fp_a, "64 lowercase hex");
    add_fp(std::string(32, 'a'), "32 chars: minimum");
    add_fp(std::string(128, 'f'), "128 chars: maximum");
    add_fp(std::string(31, 'a'), "31 chars: too short");
    add_fp(std::string(129, 'a'), "129 chars: too long");
    add_fp(util::to_lower(f.fp_a).substr(0, 63) + "A", "uppercase hex digit: invalid (callers lowercase first)");
    add_fp(std::string(63, 'a') + "g", "non-hex character");
    add_fp("", "empty");
    j["is_valid_fingerprint"] = {{"rule", "32..128 characters, each in [0-9a-f]"}, {"cases", fps}};

    json uu = json::array();
    auto add_uu = [&](const std::string& in, const char* note) {
        uu.push_back({{"input", in}, {"valid", util::is_uuid_v4(in)}, {"note", note}});
    };
    add_uu(kMsgId, "lowercase v4");
    add_uu("3B241101-E2BB-4255-8CAF-4136C566A962", "uppercase accepted");
    add_uu("3b241101-e2bb-1255-8caf-4136c566a962", "version 1: invalid");
    add_uu("3b241101-e2bb-4255-7caf-4136c566a962", "variant nibble 7: invalid");
    add_uu("3b241101e2bb42558caf4136c566a962", "no dashes: invalid");
    j["is_uuid_v4"] = {{"rule", "36 chars, dashes at 8/13/18/23, hex elsewhere (either case), char 14 == '4', char 19 in 8 9 a b (either case)"},
                       {"cases", uu}};
    return j;
}

}  // namespace

int main(int argc, char** argv) {
    const bool regen = argc > 1 && std::string_view(argv[1]) == "--regen";
    if (argc > 1 && !regen) {
        std::cerr << "usage: r2r-vectors [--regen] > docs/protocol-vectors.json\n";
        return 2;
    }
    crypto::init();

    Fixtures f{Bytes(32, 0x01), Bytes(32, 0x02), hx(kSeedIdentityC), hx(kSeedRelayA), Bytes(32, 0x77), hx(kSeedRelayC),
               node(Bytes(32, 0x01)), node(Bytes(32, 0x02)), node(hx(kSeedIdentityC)),
               node(hx(kSeedRelayA)), node(Bytes(32, 0x77)), node(hx(kSeedRelayC))};
    f.fp_a = crypto::fingerprint(f.id_a.ed_pub());
    f.fp_b = crypto::fingerprint(f.id_b.ed_pub());
    f.fp_c = crypto::fingerprint(f.id_c.ed_pub());

    // Once-generated blobs: embedded constants, or fresh ones under --regen.
    Bytes seal_blob, multi_blob, onion_blob, onion2_blob;
    if (regen) {
        auto s = crypto::seal(f.relay_a.x_pub(), std::string_view(kSealPlain));
        auto m = crypto::seal_multi({f.relay_a.x_pub(), f.relay_b.x_pub()}, bytes_of(kMultiPlain));
        onion::Terminal term;
        term.to = f.fp_a;
        term.home = kAdvertiseB;
        term.msg_id = kMsgId;
        term.from_hint = kOnionHint;
        term.body = bytes_of(kOnionBody);
        auto o1 = onion::build({{{kAdvertiseA, f.relay_a.x_pub_b64()}}, {{kAdvertiseB, f.relay_b.x_pub_b64()}}}, term);
        auto o2 = onion::build({{{kAdvertiseA, f.relay_a.x_pub_b64()}},
                                {{kAdvertiseB, f.relay_b.x_pub_b64()}, {kAdvertiseC, f.relay_c.x_pub_b64()}}},
                               term);
        if (!s || !m || !o1 || !o2) fail("regeneration failed");
        seal_blob = *s;
        multi_blob = *m;
        onion_blob = *o1;
        onion2_blob = *o2;
        std::cerr << "// --regen: paste these over the constants in tools/protocol-vectors.cpp\n";
        print_constant("kSealBlobHex", seal_blob);
        print_constant("kMultiBlobHex", multi_blob);
        print_constant("kOnionBlobHex", onion_blob);
        print_constant("kOnion2BlobHex", onion2_blob);
    } else {
        if (!*kSealBlobHex || !*kMultiBlobHex || !*kOnionBlobHex || !*kOnion2BlobHex)
            fail("embedded blob constants are empty: run with --regen and paste the output into the source");
        seal_blob = hx(kSealBlobHex);
        multi_blob = hx(kMultiBlobHex);
        onion_blob = hx(kOnionBlobHex);
        onion2_blob = hx(kOnion2BlobHex);
    }

    json doc;
    doc["meta"] = section_meta();
    doc["encodings"] = section_encodings();
    doc["identity"] = section_identity(f);
    doc["node_identity"] = section_node_identity(f);
    doc["signing"] = section_signing(f);
    doc["ed25519_verify"] = section_ed25519_verify(f);
    doc["hmac_and_turn"] = section_hmac_and_turn(f);
    doc["sealed_box"] = section_sealed_box(f, seal_blob);
    doc["multi_recipient_layer"] = section_multi(f, multi_blob);
    doc["onion"] = section_onion(f, onion_blob, onion2_blob);
    doc["addressing"] = section_addressing(f);
    doc["invite_codes_and_fingerprints"] = section_invites_and_fingerprints(f);

    std::cout << doc.dump(2) << "\n";
    return 0;
}
