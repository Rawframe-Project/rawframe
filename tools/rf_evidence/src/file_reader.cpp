#include "file_reader.h"

#include <fstream>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

Result<simdjson::padded_string> readBoundedFile(const std::filesystem::path& path, std::size_t maximumBytes) {
    std::error_code error;
    const auto kSize = std::filesystem::file_size(path, error);
    if (error) {
        return std::unexpected(
            Failure{FailureCode::MissingInput, path.generic_string(), "file is missing or unreadable"});
    }
    if (kSize > maximumBytes) {
        return std::unexpected(
            Failure{FailureCode::LimitExceeded, path.generic_string(), "file exceeds its byte limit"});
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::unexpected(Failure{FailureCode::IoFailure, path.generic_string(), "failed to open file"});
    }

    std::string bytes(static_cast<std::size_t>(kSize), '\0');
    if (!bytes.empty()) {
        input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    if (!input || input.gcount() != static_cast<std::streamsize>(bytes.size())) {
        return std::unexpected(
            Failure{FailureCode::IoFailure, path.generic_string(), "failed to read exact file bytes"});
    }
    if (!simdjson::validate_utf8(bytes)) {
        return std::unexpected(Failure{FailureCode::InvalidJson, path.generic_string(), "text is not valid UTF-8"});
    }
    if (std::string_view{bytes}.starts_with("\xEF\xBB\xBF")) {
        return std::unexpected(Failure{FailureCode::InvalidJson, path.generic_string(), "UTF-8 BOM is forbidden"});
    }

    return simdjson::padded_string(bytes);
}

} // namespace rawframe::tool::evidence
