#pragma once

#include "failure.h"

#include <cstddef>
#include <filesystem>

namespace rawframe::tool::evidence {

struct OfflineVerificationReport {
    std::size_t checkedArtifacts;
    std::uintmax_t checkedBytes;
};

[[nodiscard]] Result<OfflineVerificationReport> verifyOfflineInputs(const std::filesystem::path& repositoryRoot,
                                                                    std::string_view hostId);

} // namespace rawframe::tool::evidence
