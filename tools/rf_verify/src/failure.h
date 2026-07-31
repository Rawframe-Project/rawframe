#pragma once

#include <cstdint>
#include <expected>
#include <string>

namespace rawframe::tool::verify {

// Everything here is a statement about the tool or its inputs, never a verdict
// about the change under measurement. A change that falls below a floor is a
// Finding and a successful run; an input the tool cannot read produces one of
// these and no verdict at all. Merging the two would let a broken coverage
// export report as a repository that met every floor.
enum class FailureCode : std::uint8_t {
    InvalidArguments,
    InvalidJson,
    InvalidPath,
    IoFailure,
    LimitExceeded,
    MalformedDiff,
    MissingInput,
    NoChangedLines,
    UncoveredChangedFile,
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
    case FailureCode::InvalidJson:
        return "invalid_json";
    case FailureCode::InvalidPath:
        return "invalid_path";
    case FailureCode::IoFailure:
        return "io_failure";
    case FailureCode::LimitExceeded:
        return "limit_exceeded";
    case FailureCode::MalformedDiff:
        return "malformed_diff";
    case FailureCode::MissingInput:
        return "missing_input";
    case FailureCode::NoChangedLines:
        return "no_changed_lines";
    case FailureCode::UncoveredChangedFile:
        return "uncovered_changed_file";
    }
    return "unknown_failure";
}

// The invocation was wrong is the only failure that is not this tool's own
// problem, so it is the only one that maps to exit 2. Everything else means the
// tool could not complete and nothing can be concluded about the change.
[[nodiscard]] constexpr bool isUsageFailure(FailureCode code) noexcept {
    return code == FailureCode::InvalidArguments;
}

} // namespace rawframe::tool::verify
