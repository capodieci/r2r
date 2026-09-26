#include "crypto.hpp"

#include <cctype>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>

#include <cstring>
#include <memory>
#include <stdexcept>

#include "log.hpp"
#include "util.hpp"

namespace r2r::crypto {
namespace {

struct PkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct PkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct MdCtxDeleter { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };
struct CipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };

using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

constexpr char kSealInfo[] = "r2r-seal-v1";
constexpr char kX25519Info[] = "r2r-x25519-v1";
constexpr char kNodeIdDomain[] = "r2r-node-v1";
constexpr char kFingerprintDomain[] = "r2r-id-v1";
constexpr std::uint8_t kSealVersion = 0x01;

// HKDF-SHA256 via EVP_PKEY_CTX: available on OpenSSL 1.1.1 and 3.x alike.
std::optional<Bytes> hkdf_sha256(const Bytes& ikm, const Bytes& salt, std::string_view info,
                                 std::size_t out_len) {
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!ctx) return std::nullopt;
    if (EVP_PKEY_derive_init(ctx.get()) <= 0) return std::nullopt;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0) return std::nullopt;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), ikm.data(), static_cast<int>(ikm.size())) <= 0)
        return std::nullopt;
    if (!salt.empty() &&
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), static_cast<int>(salt.size())) <= 0)
        return std::nullopt;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx.get(),
                                    reinterpret_cast<const unsigned char*>(info.data()),
                                    static_cast<int>(info.size())) <= 0)
        return std::nullopt;
    Bytes out(out_len);
    std::size_t len = out_len;
    if (EVP_PKEY_derive(ctx.get(), out.data(), &len) <= 0 || len != out_len) return std::nullopt;
    return out;
}

std::optional<Bytes> x25519_shared(const Bytes& our_priv, const Bytes& peer_pub) {
    if (our_priv.size() != kPubLen || peer_pub.size() != kPubLen) return std::nullopt;
    PkeyPtr priv(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, our_priv.data(), kPubLen));
    PkeyPtr pub(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), kPubLen));
    if (!priv || !pub) return std::nullopt;
    PkeyCtxPtr ctx(EVP_PKEY_CTX_new(priv.get(), nullptr));
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0) return std::nullopt;
    if (EVP_PKEY_derive_set_peer(ctx.get(), pub.get()) <= 0) return std::nullopt;
    std::size_t len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &len) <= 0) return std::nullopt;
    Bytes secret(len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &len) <= 0) return std::nullopt;
    secret.resize(len);
    // An all-zero shared secret means a small-order peer key: reject it.
    std::uint8_t acc = 0;
    for (std::uint8_t b : secret) acc |= b;
    if (acc == 0) return std::nullopt;
    return secret;
}

std::optional<Bytes> x25519_public_from_private(const Bytes& priv) {
    PkeyPtr k(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), priv.size()));
    if (!k) return std::nullopt;
    Bytes pub(kPubLen);
    std::size_t len = kPubLen;
    if (EVP_PKEY_get_raw_public_key(k.get(), pub.data(), &len) <= 0 || len != kPubLen)
        return std::nullopt;
    return pub;
}

std::optional<Bytes> ed25519_public_from_seed(const Bytes& seed) {
    PkeyPtr k(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()));
    if (!k) return std::nullopt;
    Bytes pub(kPubLen);
    std::size_t len = kPubLen;
    if (EVP_PKEY_get_raw_public_key(k.get(), pub.data(), &len) <= 0 || len != kPubLen)
        return std::nullopt;
    return pub;
}

std::optional<Bytes> aes_gcm_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                                     const void* pt, std::size_t pt_len) {
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return std::nullopt;
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return std::nullopt;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()),
                            nullptr) != 1)
        return std::nullopt;
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        return std::nullopt;
    int outl = 0;
    if (!aad.empty() &&
        EVP_EncryptUpdate(ctx.get(), nullptr, &outl, aad.data(), static_cast<int>(aad.size())) != 1)
        return std::nullopt;

    Bytes out(pt_len + kTagLen);
    // `outl` still holds the AAD length here; with an empty plaintext the
    // update below is skipped and the tag would land aad.size() bytes past
    // the buffer. Count only ciphertext bytes.
    outl = 0;
    if (pt_len > 0 &&
        EVP_EncryptUpdate(ctx.get(), out.data(), &outl, static_cast<const unsigned char*>(pt),
                          static_cast<int>(pt_len)) != 1)
        return std::nullopt;
    int total = outl;
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + total, &outl) != 1) return std::nullopt;
    total += outl;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, static_cast<int>(kTagLen),
                            out.data() + total) != 1)
        return std::nullopt;
    out.resize(static_cast<std::size_t>(total) + kTagLen);
    return out;
}

std::optional<Bytes> aes_gcm_decrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                                     const std::uint8_t* ct, std::size_t ct_len) {
    if (ct_len < kTagLen) return std::nullopt;
    const std::size_t body = ct_len - kTagLen;
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return std::nullopt;
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return std::nullopt;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()),
                            nullptr) != 1)
        return std::nullopt;
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        return std::nullopt;
    int outl = 0;
    if (!aad.empty() &&
        EVP_DecryptUpdate(ctx.get(), nullptr, &outl, aad.data(), static_cast<int>(aad.size())) != 1)
        return std::nullopt;
    Bytes out(body ? body : 1);
    outl = 0;  // same as in encrypt: the AAD update's length is not plaintext
    if (body > 0 &&
        EVP_DecryptUpdate(ctx.get(), out.data(), &outl, ct, static_cast<int>(body)) != 1)
        return std::nullopt;
    int total = outl;
    Bytes tag(ct + body, ct + ct_len);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, static_cast<int>(kTagLen),
                            tag.data()) != 1)
        return std::nullopt;
    if (EVP_DecryptFinal_ex(ctx.get(), out.data() + total, &outl) != 1) return std::nullopt;
    total += outl;
    out.resize(static_cast<std::size_t>(total));
    return out;
}

}  // namespace

void init() {
    // OpenSSL 1.1+/3.x self-initialise; force an early RNG check so a broken
    // entropy source fails at startup instead of mid-handshake.
    unsigned char probe[8];
    if (RAND_bytes(probe, sizeof probe) != 1)
        throw std::runtime_error("OpenSSL RNG is not available");
}

std::string openssl_version() { return OPENSSL_VERSION_TEXT; }

Bytes random_bytes(std::size_t n) {
    Bytes out(n);
    if (n && RAND_bytes(out.data(), static_cast<int>(n)) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return out;
}

void secure_zero(void* p, std::size_t n) { OPENSSL_cleanse(p, n); }

std::string uuid_v4() {
    Bytes b = random_bytes(16);
    b[6] = static_cast<std::uint8_t>((b[6] & 0x0f) | 0x40);  // version 4
    b[8] = static_cast<std::uint8_t>((b[8] & 0x3f) | 0x80);  // RFC 4122 variant
    const std::string h = util::hex_encode(b);
    return h.substr(0, 8) + "-" + h.substr(8, 4) + "-" + h.substr(12, 4) + "-" + h.substr(16, 4) +
           "-" + h.substr(20, 12);
}

std::string invite_code(const std::string& hint_hex) {
    // Crockford base32: no I, L, O or U, so a code survives handwriting,
    // dictation and OCR intact.
    static const char kAlphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    const Bytes b = random_bytes(8);
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | b[static_cast<std::size_t>(i)];

    std::string code = "R2R-";
    if (hint_hex.size() == 8) code += hint_hex.substr(0, 4) + "-" + hint_hex.substr(4, 4) + "-";
    for (int i = 0; i < 12; ++i) {  // 12 chars x 5 bits = 60 bits of entropy
        if (i && i % 4 == 0) code += '-';
        code += kAlphabet[(v >> (55 - 5 * i)) & 0x1f];
    }
    return code;
}

Bytes sha256(const void* data, std::size_t len) {
    Bytes out(32);
    unsigned int outlen = 32;
    if (EVP_Digest(data, len, out.data(), &outlen, EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("SHA-256 failed");
    return out;
}

std::string fingerprint(const Bytes& pubkey) {
    Bytes buf;
    buf.reserve(sizeof(kFingerprintDomain) - 1 + pubkey.size());
    buf.insert(buf.end(), kFingerprintDomain, kFingerprintDomain + sizeof(kFingerprintDomain) - 1);
    buf.insert(buf.end(), pubkey.begin(), pubkey.end());
    return util::hex_encode(sha256(buf.data(), buf.size()));
}

std::string contact_address(const Bytes& pub) {
    if (pub.size() != kPubLen) return {};
    Bytes buf(pub);
    buf.insert(buf.end(), {'R', '2', 'R'});
    unsigned char digest[32];
    unsigned int len = 0;
    if (EVP_Digest(buf.data(), buf.size(), digest, &len, EVP_sha3_256(), nullptr) != 1 || len != 32)
        return {};
    Bytes raw(pub);
    raw.insert(raw.end(), digest, digest + 3);
    static const char kB32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string s;
    std::uint32_t acc = 0;
    int bits = 0;
    for (std::uint8_t b : raw) {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 5) {
            s += kB32[(acc >> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) s += kB32[(acc << (5 - bits)) & 31];
    std::string out = "R2R";
    for (std::size_t i = 0; i < s.size(); i += 8) out += "_" + s.substr(i, 8);
    return out;
}

std::optional<Bytes> pubkey_from_contact_address(std::string_view addr) {
    static const char kB32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string s;
    for (char c : addr) {
        if (c == '_' || c == '-' || c == ' ') continue;
        s += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    if (s.compare(0, 3, "R2R") == 0) s.erase(0, 3);
    if (s.size() != 56) return std::nullopt;  // 35 bytes: 32 key + 3 checksum
    Bytes raw;
    std::uint32_t acc = 0;
    int bits = 0;
    for (char c : s) {
        const char* p = std::strchr(kB32, c);
        if (c == '\0' || !p) return std::nullopt;
        acc = (acc << 5) | static_cast<std::uint32_t>(p - kB32);
        bits += 5;
        if (bits >= 8) {
            raw.push_back(static_cast<std::uint8_t>((acc >> (bits - 8)) & 0xFF));
            bits -= 8;
        }
    }
    if (raw.size() < kPubLen + 3) return std::nullopt;
    Bytes pub(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(kPubLen));
    Bytes buf(pub);
    buf.insert(buf.end(), {'R', '2', 'R'});
    unsigned char digest[32];
    unsigned int len = 0;
    if (EVP_Digest(buf.data(), buf.size(), digest, &len, EVP_sha3_256(), nullptr) != 1 || len != 32)
        return std::nullopt;
    if (std::memcmp(digest, raw.data() + kPubLen, 3) != 0) return std::nullopt;
    return pub;
}

std::string node_id_from_ed_pub(const Bytes& ed_pub) {
    Bytes buf;
    buf.reserve(sizeof(kNodeIdDomain) - 1 + ed_pub.size());
    buf.insert(buf.end(), kNodeIdDomain, kNodeIdDomain + sizeof(kNodeIdDomain) - 1);
    buf.insert(buf.end(), ed_pub.begin(), ed_pub.end());
    return util::hex_encode(sha256(buf.data(), buf.size())).substr(0, 32);
}

// ------------------------------------------------------- NodeIdentity ------

NodeIdentity::~NodeIdentity() {
    if (!seed_.empty()) secure_zero(seed_.data(), seed_.size());
    if (!x_priv_.empty()) secure_zero(x_priv_.data(), x_priv_.size());
}

NodeIdentity::NodeIdentity(NodeIdentity&&) noexcept = default;
NodeIdentity& NodeIdentity::operator=(NodeIdentity&&) noexcept = default;

std::optional<NodeIdentity> NodeIdentity::from_seed(const Bytes& seed) {
    if (seed.size() != kSeedLen) return std::nullopt;

    auto x_priv = hkdf_sha256(seed, Bytes{}, kX25519Info, kPubLen);
    if (!x_priv) return std::nullopt;
    auto x_pub = x25519_public_from_private(*x_priv);
    auto ed_pub = ed25519_public_from_seed(seed);
    if (!x_pub || !ed_pub) return std::nullopt;

    NodeIdentity id;
    id.seed_ = seed;
    id.x_priv_ = *x_priv;
    id.x_pub_ = *x_pub;
    id.ed_pub_ = *ed_pub;
    id.node_id_ = node_id_from_ed_pub(*ed_pub);
    id.ed_pub_b64_ = util::b64_encode(*ed_pub);
    id.x_pub_b64_ = util::b64_encode(*x_pub);
    return id;
}

std::optional<NodeIdentity> NodeIdentity::generate() { return from_seed(random_bytes(kSeedLen)); }

std::optional<NodeIdentity> NodeIdentity::load_or_create(const std::string& key_path) {
    if (auto raw = util::read_file(key_path)) {
        std::string data = util::trim(*raw);
        Bytes seed;
        if (data.size() == kSeedLen * 2) {
            if (auto d = util::hex_decode(data)) seed = *d;
        } else if (raw->size() == kSeedLen) {
            seed.assign(raw->begin(), raw->end());
        }
        if (seed.size() != kSeedLen) {
            log::error("node key at ", key_path, " is malformed (expected 32 raw or 64 hex bytes)");
            return std::nullopt;
        }
        return from_seed(seed);
    }

    const Bytes seed = random_bytes(kSeedLen);
    if (!util::make_dirs(util::dirname_of(key_path), 0700)) {
        log::error("cannot create directory for node key: ", util::dirname_of(key_path));
        return std::nullopt;
    }
    if (!util::write_file_atomic(key_path, util::hex_encode(seed) + "\n", 0600)) {
        log::error("cannot persist node key to ", key_path);
        return std::nullopt;
    }
    log::info("generated a new node identity at ", key_path);
    return from_seed(seed);
}

std::optional<Bytes> NodeIdentity::sign(std::string_view msg) const {
    PkeyPtr key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed_.data(), seed_.size()));
    if (!key) return std::nullopt;
    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) return std::nullopt;
    if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1)
        return std::nullopt;
    std::size_t siglen = 0;
    const auto* m = reinterpret_cast<const unsigned char*>(msg.data());
    if (EVP_DigestSign(ctx.get(), nullptr, &siglen, m, msg.size()) != 1) return std::nullopt;
    Bytes sig(siglen);
    if (EVP_DigestSign(ctx.get(), sig.data(), &siglen, m, msg.size()) != 1) return std::nullopt;
    sig.resize(siglen);
    return sig;
}

std::optional<Bytes> NodeIdentity::unseal(const Bytes& blob) const {
    return crypto::unseal(x_priv_, x_pub_, blob);
}

std::optional<Bytes> NodeIdentity::unseal_multi(const Bytes& blob) const {
    return crypto::unseal_multi(x_priv_, x_pub_, blob);
}

bool verify_signature(const Bytes& ed_pub, std::string_view msg, const Bytes& sig) {
    if (ed_pub.size() != kPubLen || sig.empty()) return false;
    PkeyPtr key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, ed_pub.data(), kPubLen));
    if (!key) return false;
    MdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx) return false;
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1) return false;
    const auto* m = reinterpret_cast<const unsigned char*>(msg.data());
    return EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), m, msg.size()) == 1;
}

namespace {
Bytes hmac_with(const EVP_MD* md, std::string_view key, std::string_view msg) {
    unsigned int len = 0;
    Bytes out(EVP_MAX_MD_SIZE);
    if (!HMAC(md, key.data(), static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), out.data(), &len))
        return {};
    out.resize(len);
    return out;
}
}  // namespace

Bytes hmac_sha1(std::string_view key, std::string_view msg) {
    return hmac_with(EVP_sha1(), key, msg);
}

Bytes hmac_sha256(std::string_view key, std::string_view msg) {
    return hmac_with(EVP_sha256(), key, msg);
}

// ---------------------------------------------------------- sealed box -----

std::optional<Bytes> seal(const Bytes& recipient_x_pub, const void* plaintext, std::size_t len) {
    if (recipient_x_pub.size() != kPubLen) return std::nullopt;

    const Bytes eph_priv = random_bytes(kPubLen);
    auto eph_pub = x25519_public_from_private(eph_priv);
    if (!eph_pub) return std::nullopt;
    auto shared = x25519_shared(eph_priv, recipient_x_pub);
    if (!shared) return std::nullopt;

    Bytes salt;
    salt.insert(salt.end(), eph_pub->begin(), eph_pub->end());
    salt.insert(salt.end(), recipient_x_pub.begin(), recipient_x_pub.end());
    auto key = hkdf_sha256(*shared, salt, kSealInfo, 32);
    if (!key) return std::nullopt;

    const Bytes nonce = random_bytes(kNonceLen);

    Bytes header;
    header.push_back(kSealVersion);
    header.insert(header.end(), eph_pub->begin(), eph_pub->end());

    Bytes aad = header;
    aad.insert(aad.end(), recipient_x_pub.begin(), recipient_x_pub.end());

    auto ct = aes_gcm_encrypt(*key, nonce, aad, plaintext, len);
    if (!ct) return std::nullopt;

    Bytes out;
    out.reserve(header.size() + nonce.size() + ct->size());
    out.insert(out.end(), header.begin(), header.end());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ct->begin(), ct->end());
    return out;
}

std::optional<Bytes> unseal(const Bytes& our_x_priv, const Bytes& our_x_pub, const Bytes& blob) {
    if (blob.size() < kSealOverhead) return std::nullopt;
    if (blob[0] != kSealVersion) return std::nullopt;

    const Bytes eph_pub(blob.begin() + 1, blob.begin() + 1 + kPubLen);
    const Bytes nonce(blob.begin() + 1 + kPubLen, blob.begin() + 1 + kPubLen + kNonceLen);
    const std::uint8_t* ct = blob.data() + 1 + kPubLen + kNonceLen;
    const std::size_t ct_len = blob.size() - 1 - kPubLen - kNonceLen;

    auto shared = x25519_shared(our_x_priv, eph_pub);
    if (!shared) return std::nullopt;

    Bytes salt;
    salt.insert(salt.end(), eph_pub.begin(), eph_pub.end());
    salt.insert(salt.end(), our_x_pub.begin(), our_x_pub.end());
    auto key = hkdf_sha256(*shared, salt, kSealInfo, 32);
    if (!key) return std::nullopt;

    Bytes aad;
    aad.push_back(kSealVersion);
    aad.insert(aad.end(), eph_pub.begin(), eph_pub.end());
    aad.insert(aad.end(), our_x_pub.begin(), our_x_pub.end());

    return aes_gcm_decrypt(*key, nonce, aad, ct, ct_len);
}

// --------------------------------------------------- multi-recipient -----

std::optional<Bytes> seal_multi(const std::vector<Bytes>& recipients, const Bytes& plaintext) {
    if (recipients.empty() || recipients.size() > kMaxSlots) return std::nullopt;
    const Bytes key = random_bytes(32);
    Bytes out;
    out.push_back(kMultiVersion);
    out.push_back(static_cast<std::uint8_t>(recipients.size()));
    for (const auto& r : recipients) {
        auto slot = seal(r, key.data(), key.size());
        if (!slot || slot->size() != kSlotLen) return std::nullopt;
        out.insert(out.end(), slot->begin(), slot->end());
    }
    const Bytes aad = out;
    const Bytes nonce = random_bytes(kNonceLen);
    auto ct = aes_gcm_encrypt(key, nonce, aad, plaintext.data(), plaintext.size());
    if (!ct) return std::nullopt;
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ct->begin(), ct->end());
    return out;
}

std::optional<Bytes> unseal_multi(const Bytes& our_x_priv, const Bytes& our_x_pub, const Bytes& blob) {
    if (blob.size() < kMultiMin || blob[0] != kMultiVersion) return std::nullopt;
    const std::size_t n = blob[1];
    if (n == 0 || n > kMaxSlots) return std::nullopt;
    const std::size_t header = 2 + n * kSlotLen;
    if (blob.size() < header + kNonceLen + kTagLen) return std::nullopt;
    // Try every slot: which one is ours is not written anywhere, so the layer
    // itself never says which candidate it was meant for first.
    std::optional<Bytes> key;
    for (std::size_t i = 0; i < n && !key; ++i) {
        const Bytes slot(blob.begin() + 2 + i * kSlotLen, blob.begin() + 2 + (i + 1) * kSlotLen);
        auto k = unseal(our_x_priv, our_x_pub, slot);
        if (k && k->size() == 32) key = std::move(k);
    }
    if (!key) return std::nullopt;
    const Bytes aad(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(header));
    const Bytes nonce(blob.begin() + static_cast<std::ptrdiff_t>(header),
                      blob.begin() + static_cast<std::ptrdiff_t>(header + kNonceLen));
    return aes_gcm_decrypt(*key, nonce, aad, blob.data() + header + kNonceLen,
                           blob.size() - header - kNonceLen);
}

// ---- EVM helpers -------------------------------------------------------------

namespace {

// Keccak-f[1600] on 25 lanes; the sponge below uses rate 136 (Keccak-256).
void keccak_f1600(std::uint64_t st[25]) {
    static const std::uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
    static const int R[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
                              25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};
    const auto rotl = [](std::uint64_t x, int n) { return n ? (x << n) | (x >> (64 - n)) : x; };
    for (int round = 0; round < 24; ++round) {
        std::uint64_t C[5], D[5], B[25];
        for (int x = 0; x < 5; ++x) C[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        for (int x = 0; x < 5; ++x) D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
        for (int i = 0; i < 25; ++i) st[i] ^= D[i % 5];
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(st[x + 5 * y], R[x + 5 * y]);
        for (int x = 0; x < 5; ++x)
            for (int y = 0; y < 5; ++y)
                st[x + 5 * y] = B[x + 5 * y] ^ (~B[(x + 1) % 5 + 5 * y] & B[(x + 2) % 5 + 5 * y]);
        st[0] ^= RC[round];
    }
}

Bytes hex_addr(const unsigned char* pub64) {
    Bytes h = keccak256(pub64, 64);
    return Bytes(h.begin() + 12, h.end());
}

std::optional<Bytes> addr_bytes(std::string_view hex0x) {
    if (hex0x.size() != 42 || hex0x[0] != '0' || (hex0x[1] != 'x' && hex0x[1] != 'X'))
        return std::nullopt;
    auto b = util::hex_decode(hex0x.substr(2));
    if (!b || b->size() != 20) return std::nullopt;
    return b;
}

void put_uint256(Bytes& out, std::int64_t v) {
    for (int i = 0; i < 24; ++i) out.push_back(0);
    for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>((static_cast<std::uint64_t>(v) >> (8 * i)) & 0xff));
}

struct BnFree { void operator()(BIGNUM* b) const { BN_free(b); } };
struct BnCtxFree { void operator()(BN_CTX* c) const { BN_CTX_free(c); } };
struct GroupFree { void operator()(EC_GROUP* g) const { EC_GROUP_free(g); } };
struct PointFree { void operator()(EC_POINT* p) const { EC_POINT_free(p); } };
using BnPtr = std::unique_ptr<BIGNUM, BnFree>;
using BnCtxPtr = std::unique_ptr<BN_CTX, BnCtxFree>;
using GroupPtr = std::unique_ptr<EC_GROUP, GroupFree>;
using PointPtr = std::unique_ptr<EC_POINT, PointFree>;

// secp256k1 n / 2, the malleability boundary the vault contract enforces.
const char* const kHalfOrderHex = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0";

}  // namespace

Bytes keccak256(const void* data, std::size_t len) {
    std::uint64_t st[25] = {0};
    const auto* in = static_cast<const std::uint8_t*>(data);
    constexpr std::size_t rate = 136;
    std::uint8_t block[rate];
    std::size_t off = 0;
    const auto absorb = [&](const std::uint8_t* b) {
        for (std::size_t i = 0; i < rate / 8; ++i) {
            std::uint64_t lane = 0;
            for (int k = 7; k >= 0; --k) lane = (lane << 8) | b[i * 8 + k];
            st[i] ^= lane;
        }
        keccak_f1600(st);
    };
    while (len - off >= rate) {
        absorb(in + off);
        off += rate;
    }
    std::memset(block, 0, rate);
    std::memcpy(block, in + off, len - off);
    block[len - off] ^= 0x01;   // Keccak padding (SHA-3 would use 0x06)
    block[rate - 1] ^= 0x80;
    absorb(block);
    Bytes out(32);
    for (int i = 0; i < 4; ++i)
        for (int k = 0; k < 8; ++k) out[i * 8 + k] = static_cast<std::uint8_t>(st[i] >> (8 * k));
    return out;
}

Bytes evm_voucher_digest(std::string_view vault, std::int64_t chain_id, std::string_view payee,
                         std::int64_t cumulative_micro) {
    auto v = addr_bytes(vault);
    auto p = addr_bytes(payee);
    if (!v || !p || chain_id <= 0 || cumulative_micro < 0) return {};
    Bytes m;
    const std::string tag = "r2r-voucher-v1";
    m.insert(m.end(), tag.begin(), tag.end());
    m.insert(m.end(), v->begin(), v->end());
    put_uint256(m, chain_id);
    m.insert(m.end(), p->begin(), p->end());
    put_uint256(m, cumulative_micro);
    const Bytes inner = keccak256(m);
    const std::string prefix = "\x19" "Ethereum Signed Message:\n32";
    Bytes outer(prefix.begin(), prefix.end());
    outer.insert(outer.end(), inner.begin(), inner.end());
    return keccak256(outer);
}

std::optional<std::string> evm_recover_address(const Bytes& digest32, const Bytes& sig65) {
    if (digest32.size() != 32 || sig65.size() != 65) return std::nullopt;
    int v = sig65[64];
    if (v >= 27) v -= 27;
    if (v != 0 && v != 1) return std::nullopt;

    GroupPtr group(EC_GROUP_new_by_curve_name(NID_secp256k1));
    BnCtxPtr ctx(BN_CTX_new());
    if (!group || !ctx) return std::nullopt;
    BnPtr r(BN_bin2bn(sig65.data(), 32, nullptr));
    BnPtr s(BN_bin2bn(sig65.data() + 32, 32, nullptr));
    BnPtr e(BN_bin2bn(digest32.data(), 32, nullptr));
    BnPtr n(BN_new()), half(nullptr), rinv(BN_new()), u1(BN_new()), u2(BN_new());
    if (!r || !s || !e || !n || !rinv || !u1 || !u2) return std::nullopt;
    if (EC_GROUP_get_order(group.get(), n.get(), ctx.get()) != 1) return std::nullopt;
    BIGNUM* half_raw = nullptr;
    if (BN_hex2bn(&half_raw, kHalfOrderHex) == 0) return std::nullopt;
    half.reset(half_raw);
    if (BN_is_zero(r.get()) || BN_is_zero(s.get()) || BN_cmp(r.get(), n.get()) >= 0 ||
        BN_cmp(s.get(), half.get()) > 0)
        return std::nullopt;

    // R = the curve point with x = r and the parity v names.
    PointPtr R(EC_POINT_new(group.get()));
    if (!R || EC_POINT_set_compressed_coordinates(group.get(), R.get(), r.get(), v, ctx.get()) != 1)
        return std::nullopt;
    // Q = r^-1 (s·R − e·G)
    if (!BN_mod_inverse(rinv.get(), r.get(), n.get(), ctx.get())) return std::nullopt;
    if (BN_mod_mul(u2.get(), s.get(), rinv.get(), n.get(), ctx.get()) != 1) return std::nullopt;
    if (BN_mod_mul(u1.get(), e.get(), rinv.get(), n.get(), ctx.get()) != 1) return std::nullopt;
    if (BN_sub(u1.get(), n.get(), u1.get()) != 1) return std::nullopt;  // −e·r^-1 mod n
    PointPtr Q(EC_POINT_new(group.get()));
    if (!Q || EC_POINT_mul(group.get(), Q.get(), u1.get(), R.get(), u2.get(), ctx.get()) != 1)
        return std::nullopt;
    if (EC_POINT_is_at_infinity(group.get(), Q.get())) return std::nullopt;
    unsigned char pub[65];
    if (EC_POINT_point2oct(group.get(), Q.get(), POINT_CONVERSION_UNCOMPRESSED, pub, sizeof pub,
                           ctx.get()) != sizeof pub)
        return std::nullopt;
    return "0x" + util::hex_encode(hex_addr(pub + 1));
}

std::optional<std::string> evm_address_of(const Bytes& priv32) {
    if (priv32.size() != 32) return std::nullopt;
    GroupPtr group(EC_GROUP_new_by_curve_name(NID_secp256k1));
    BnCtxPtr ctx(BN_CTX_new());
    BnPtr d(BN_bin2bn(priv32.data(), 32, nullptr));
    if (!group || !ctx || !d) return std::nullopt;
    PointPtr Q(EC_POINT_new(group.get()));
    if (!Q || EC_POINT_mul(group.get(), Q.get(), d.get(), nullptr, nullptr, ctx.get()) != 1)
        return std::nullopt;
    unsigned char pub[65];
    if (EC_POINT_point2oct(group.get(), Q.get(), POINT_CONVERSION_UNCOMPRESSED, pub, sizeof pub,
                           ctx.get()) != sizeof pub)
        return std::nullopt;
    return "0x" + util::hex_encode(hex_addr(pub + 1));
}

std::optional<Bytes> evm_sign(const Bytes& priv32, const Bytes& digest32) {
    if (priv32.size() != 32 || digest32.size() != 32) return std::nullopt;
    auto address = evm_address_of(priv32);
    if (!address) return std::nullopt;

    // Build an EVP key from the raw scalar (the non-deprecated route in 3.x).
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) return std::nullopt;
    BnPtr d(BN_bin2bn(priv32.data(), 32, nullptr));
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "secp256k1", 0);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d.get());
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) return std::nullopt;
    EVP_PKEY* raw = nullptr;
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    const bool made = kctx && EVP_PKEY_fromdata_init(kctx) == 1 &&
                      EVP_PKEY_fromdata(kctx, &raw, EVP_PKEY_KEYPAIR, params) == 1;
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(kctx);
    if (!made || !raw) return std::nullopt;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(raw, EVP_PKEY_free);

    EVP_PKEY_CTX* sctx = EVP_PKEY_CTX_new(key.get(), nullptr);
    if (!sctx) return std::nullopt;
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> sguard(sctx, EVP_PKEY_CTX_free);
    std::size_t der_len = 0;
    if (EVP_PKEY_sign_init(sctx) != 1 ||
        EVP_PKEY_sign(sctx, nullptr, &der_len, digest32.data(), digest32.size()) != 1)
        return std::nullopt;
    Bytes der(der_len);
    if (EVP_PKEY_sign(sctx, der.data(), &der_len, digest32.data(), digest32.size()) != 1)
        return std::nullopt;
    const unsigned char* pp = der.data();
    ECDSA_SIG* esig = d2i_ECDSA_SIG(nullptr, &pp, static_cast<long>(der_len));
    if (!esig) return std::nullopt;
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(esig, &r, &s);
    BnPtr s_low(BN_dup(s));
    BnPtr rr(BN_dup(r));
    ECDSA_SIG_free(esig);
    if (!s_low || !rr) return std::nullopt;

    // Low-s: if s > n/2, use n − s (the vault refuses the other half).
    GroupPtr group(EC_GROUP_new_by_curve_name(NID_secp256k1));
    BnCtxPtr ctx(BN_CTX_new());
    BnPtr n(BN_new());
    if (!group || !ctx || !n || EC_GROUP_get_order(group.get(), n.get(), ctx.get()) != 1)
        return std::nullopt;
    BIGNUM* half_raw = nullptr;
    if (BN_hex2bn(&half_raw, kHalfOrderHex) == 0) return std::nullopt;
    BnPtr half(half_raw);
    if (BN_cmp(s_low.get(), half.get()) > 0 && BN_sub(s_low.get(), n.get(), s_low.get()) != 1)
        return std::nullopt;

    Bytes sig(65, 0);
    if (BN_bn2binpad(rr.get(), sig.data(), 32) != 32 || BN_bn2binpad(s_low.get(), sig.data() + 32, 32) != 32)
        return std::nullopt;
    // The recovery id is whichever parity brings back our own address.
    for (int v = 0; v < 2; ++v) {
        sig[64] = static_cast<std::uint8_t>(27 + v);
        if (auto rec = evm_recover_address(digest32, sig); rec && *rec == *address) return sig;
    }
    return std::nullopt;
}

}  // namespace r2r::crypto
