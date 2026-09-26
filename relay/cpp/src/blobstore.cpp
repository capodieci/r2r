#include "blobstore.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include "crypto.hpp"
#include "log.hpp"

namespace r2r {

bool BlobStore::is_valid_id(std::string_view id) {
    if (id.size() != 64) return false;
    for (char c : id) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) return false;
    }
    return true;
}

bool BlobStore::open(const std::string& directory) {
    dir_ = directory;
    if (!util::make_dirs(dir_, 0700)) {
        log::error("cannot create the blob directory ", dir_);
        return false;
    }
    return true;
}

std::string BlobStore::path_for(const std::string& id) const {
    if (!is_valid_id(id)) return {};
    return util::path_join(util::path_join(dir_, id.substr(0, 2)), id);
}

std::optional<std::string> BlobStore::put(const void* data, std::size_t len) {
    if (dir_.empty() || len == 0) return std::nullopt;

    const std::string id = util::hex_encode(crypto::sha256(data, len));
    const std::string path = path_for(id);
    if (path.empty()) return std::nullopt;

    if (util::file_exists(path)) return id;  // identical content already stored

    if (!util::make_dirs(util::dirname_of(path), 0700)) return std::nullopt;
    const std::string_view bytes(static_cast<const char*>(data), len);
    if (!util::write_file_atomic(path, bytes, 0600)) {
        log::error("could not write a blob to ", path);
        return std::nullopt;
    }
    return id;
}

std::optional<util::Bytes> BlobStore::get(const std::string& id) const {
    const std::string path = path_for(id);
    if (path.empty()) return std::nullopt;
    auto raw = util::read_file(path);
    if (!raw) return std::nullopt;
    return util::Bytes(raw->begin(), raw->end());
}

bool BlobStore::exists(const std::string& id) const {
    const std::string path = path_for(id);
    return !path.empty() && util::file_exists(path);
}

bool BlobStore::remove(const std::string& id) {
    const std::string path = path_for(id);
    if (path.empty()) return false;
    return ::unlink(path.c_str()) == 0;
}

std::int64_t BlobStore::disk_usage() const {
    if (dir_.empty()) return 0;
    std::int64_t total = 0;
    for (const auto& shard : util::list_dirs(dir_)) {
        for (const auto& f : util::list_files(util::path_join(dir_, shard))) total += f.size;
    }
    return total;
}

}  // namespace r2r
