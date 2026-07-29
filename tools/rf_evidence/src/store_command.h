#pragma once

#include "blob_store.h"
#include "record_command.h"

#include <iosfwd>

namespace rawframe::tool::evidence {

// Where the store is, resolved once. The record operations that retrieve
// receipts share it rather than deriving the location a second time, because
// two places computing the same root is two roots waiting to disagree.
[[nodiscard]] BlobStore storeFor(const ParsedOptions& options);

// The content-addressed store's three operations. They share `ParsedOptions`
// and `fail` with the record operations because the command line is one
// vocabulary and an exit code must not depend on which file raised it, but they
// hold no record semantics: a blob is bytes plus a digest, and what contract
// those bytes were produced under is the caller's declaration.
[[nodiscard]] int putBlobOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors);
[[nodiscard]] int verifyBlobOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors);
[[nodiscard]] int getBlobOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors);

} // namespace rawframe::tool::evidence
