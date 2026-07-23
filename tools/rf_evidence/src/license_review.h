#pragma once

#include "failure.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace rawframe::tool::evidence {

struct LicenseMaterial {
    std::string path;
    std::uintmax_t byteSize = 0;
    std::string sha256;
};

struct LicenseReviewEntry {
    std::string licenseId;
    std::vector<std::string> catalogIds;
    std::string spdxExpression;
    std::string materialPath;
    std::string sectionHeading;
    std::string redistribution;
    std::string approval;
    std::string advisoryPolicy;
};

struct LicenseReview {
    std::vector<LicenseMaterial> materials;
    std::vector<LicenseReviewEntry> entries;
    std::size_t catalogEntryCount = 0;
    std::size_t restrictedCount = 0;
};

// Verifies the maintained license/notice material against its index and the
// dependency catalog: every material file must match its recorded exact byte
// length and SHA-256 digest, every catalog entry must be covered by exactly
// one license entry, and the indexed SPDX/redistribution/approval facts must
// agree with the catalog's license authority.
[[nodiscard]] Result<LicenseReview> reviewLicenses(const std::filesystem::path& repositoryRoot);

} // namespace rawframe::tool::evidence
