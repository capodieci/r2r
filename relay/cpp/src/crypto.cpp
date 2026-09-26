#include "crypto.hpp"

#include <cctype>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>

#include <cstring>
#include <memory>
#include <stdexcept>

#include "log.hpp"

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

}  // namespace r2r::crypto
