#pragma once

#include <cstdint>
#include <expected>
#include <string>

namespace rawframe::tool::evidence {

enum class FailureCode : std::uint8_t {
    InvalidArguments,
    InvalidJson,
    InvalidManifest,
    InvalidPath,
    IoFailure,
    LimitExceeded,
    MissingInput,
    OwnershipCollision,
    UnsupportedHost,
    VerificationFailed,
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
    case FailureCode::InvalidManifest:
        return "invalid_manifest";
    case FailureCode::InvalidPath:
        return "invalid_path";
    case FailureCode::IoFailure:
        return "io_failure";
    case FailureCode::LimitExceeded:
        return "limit_exceeded";
    case FailureCode::MissingInput:
        return "missing_input";
    case FailureCode::OwnershipCollision:
        return "ownership_collision";
    case FailureCode::UnsupportedHost:
        return "unsupported_host";
    case FailureCode::VerificationFailed:
        return "verification_failed";
    }
    return "unknown_failure";
}

} // namespace rawframe::tool::evidence
