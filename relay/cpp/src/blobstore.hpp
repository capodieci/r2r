// R2R relay -- content-addressed storage for voice and video messages.
//
// Bytes live on disk under <blob-dir>/ab/<sha256hex>, sharded by the first two
// characters so no single directory grows unbounded. SQLite holds the
// references (who owns it, when it expires); this class only owns the files.
//
// Content addressing means the same recording uploaded twice is stored once,
// and an id is self-verifying: a client that knows the id can check the bytes
// it got back are the bytes that were meant.
//
// The contents are ciphertext produced by a client. The relay stores and
// serves them and cannot read them.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "util.hpp"

namespace r2r {

class BlobStore {
public:
    bool open(const std::string& directory);

    // Returns the blob id (sha256 hex). Writing the same content twice is a
    // no-op beyond the reference the caller records.
    std::optional<std::string> put(const void* data, std::size_t len);

    std::optional<util::Bytes> get(const std::string& id) const;
    bool exists(const std::string& id) const;
    bool remove(const std::string& id);

    std::string path_for(const std::string& id) const;
    const std::string& directory() const { return dir_; }

    // Total bytes on disk, for the status page. Walks the tree, so callers
    // should not put it on a hot path.
    std::int64_t disk_usage() const;

    static bool is_valid_id(std::string_view id);

private:
    std::string dir_;
};

}  // namespace r2r
