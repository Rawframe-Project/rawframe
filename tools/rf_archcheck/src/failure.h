#pragma once

#include <cstdint>
#include <expected>
#include <string>

namespace rawframe::tool::archcheck {

// Everything here is a statement about the tool, never about the repository.
// A repository that violates an accepted authority produces a Finding and a
// successful run; a repository the tool cannot read produces one of these and
// no verdict at all. SPEC-0044 makes that distinction the difference between
// exit 1 and exit 3, and a caller that merged them would report a broken tool
// as a clean repository.
enum class FailureCode : std::uint8_t {
    InvalidArguments,
    InvalidCorpus,
    InvalidJson,
    InvalidPath,
    IoFailure,
    LimitExceeded,
    MissingInput,
};

struct Failure {
    FailureCode code;
    std::string path;
    std::string message;
};

template <typename ValueType> using Result = std::expected<ValueType, Failure>;

using Status = Result<void>;

[[nodiscard]] constexpr const char* failureCodeName(FailureCode code) noexcept {
    switch (code) {
    case FailureCode::InvalidArguments:
        return "invalid_arguments";
    case FailureCode::InvalidCorpus:
        return "invalid_corpus";
    case FailureCode::InvalidJson:
        return "invalid_json";
    case FailureCode::InvalidPath:
        return "invalid_path";
    case FailureCode::IoFailure:
        return "io_failure";
    case FailureCode::LimitExceeded:
        return "limit_exceeded";
    case FailureCode::MissingInput:
        return "missing_input";
    }
    return "unknown_failure";
}

// The invocation was wrong is the only failure that is not the tool's own
// problem, so it is the only one that maps to exit 2. Everything else means
// the tool could not complete and nothing can be concluded about the tree.
[[nodiscard]] constexpr bool isUsageFailure(FailureCode code) noexcept {
    return code == FailureCode::InvalidArguments;
}

} // namespace rawframe::tool::archcheck
