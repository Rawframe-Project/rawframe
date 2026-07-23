#include "license_review.h"

#include "file_reader.h"
#include "json_policy.h"
#include "path_policy.h"
#include "sha256.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <simdjson.h>
#include <string_view>
#include <utility>

namespace rawframe::tool::evidence {

namespace {

constexpr std::size_t kMaximumLicenseRecords = 256;

Failure invalidLicenseJson(const std::filesystem::path& path, std::string_view message) {
    return Failure{FailureCode::InvalidJson, path.generic_string(), std::string(message)};
}

Result<std::string>
requiredString(simdjson::dom::object object, std::string_view key, const std::filesystem::path& path) {
    std::string_view value;
    if (const auto kError = object.at_key(key).get_string().get(value); kError) {
        return std::unexpected(
            invalidLicenseJson(path, std::string("missing or invalid string field ") + std::string(key)));
    }
    return std::string(value);
}

struct CatalogLicenseFacts {
    std::string spdxExpression;
    std::string redistribution;
    std::string approval;
    std::string advisoryPolicy;
};

Result<std::map<std::string, CatalogLicenseFacts, std::less<>>>
readCatalogLicenseFacts(const std::filesystem::path& repositoryRoot) {
    auto catalogPath = resolveRepositoryPath(repositoryRoot, "third_party/catalog.json");
    if (!catalogPath) {
        return std::unexpected(catalogPath.error());
    }
    if (auto admission = validateJsonAdmission(*catalogPath); !admission) {
        return std::unexpected(admission.error());
    }
    auto input = readBoundedFile(*catalogPath);
    if (!input) {
        return std::unexpected(input.error());
    }

    simdjson::dom::parser parser;
    simdjson::dom::object root;
    if (const auto kError = parser.parse(*input).get_object().get(root); kError) {
        return std::unexpected(invalidLicenseJson(*catalogPath, "catalog must be a JSON object"));
    }
    simdjson::dom::array entries;
    if (const auto kError = root.at_key("entries").get_array().get(entries); kError) {
        return std::unexpected(invalidLicenseJson(*catalogPath, "catalog entries array is missing"));
    }

    std::map<std::string, CatalogLicenseFacts, std::less<>> facts;
    for (const auto kEntryElement : entries) {
        if (facts.size() >= kMaximumLicenseRecords) {
            return std::unexpected(Failure{
                FailureCode::LimitExceeded, catalogPath->generic_string(), "catalog exceeds the license review limit"});
        }
        simdjson::dom::object entry;
        if (const auto kError = kEntryElement.get_object().get(entry); kError) {
            return std::unexpected(invalidLicenseJson(*catalogPath, "catalog entry must be an object"));
        }
        auto id = requiredString(entry, "id", *catalogPath);
        if (!id) {
            return std::unexpected(id.error());
        }

        simdjson::dom::object license;
        if (const auto kError = entry.at_key("license").get_object().get(license); kError) {
            return std::unexpected(invalidLicenseJson(*catalogPath, "catalog entry lacks a license object"));
        }
        simdjson::dom::object security;
        if (const auto kError = entry.at_key("security").get_object().get(security); kError) {
            return std::unexpected(invalidLicenseJson(*catalogPath, "catalog entry lacks a security object"));
        }
        auto spdx = requiredString(license, "spdxExpression", *catalogPath);
        auto redistribution = requiredString(license, "redistribution", *catalogPath);
        auto approval = requiredString(license, "approval", *catalogPath);
        auto advisoryPolicy = requiredString(security, "advisoryPolicy", *catalogPath);
        if (!spdx || !redistribution || !approval || !advisoryPolicy) {
            return std::unexpected(invalidLicenseJson(*catalogPath, "catalog license/security facts are incomplete"));
        }

        CatalogLicenseFacts entryFacts{
            .spdxExpression = std::move(*spdx),
            .redistribution = std::move(*redistribution),
            .approval = std::move(*approval),
            .advisoryPolicy = std::move(*advisoryPolicy),
        };
        if (!facts.emplace(std::move(*id), std::move(entryFacts)).second) {
            return std::unexpected(Failure{
                FailureCode::OwnershipCollision, catalogPath->generic_string(), "catalog contains a duplicate ID"});
        }
    }
    return facts;
}

Result<std::vector<LicenseMaterial>> verifyMaterials(const std::filesystem::path& repositoryRoot,
                                                     simdjson::dom::object indexRoot,
                                                     const std::filesystem::path& indexPath) {
    simdjson::dom::array materialsArray;
    if (const auto kError = indexRoot.at_key("materials").get_array().get(materialsArray); kError) {
        return std::unexpected(invalidLicenseJson(indexPath, "license index lacks a materials array"));
    }

    std::vector<LicenseMaterial> materials;
    std::set<std::string, std::less<>> seenPaths;
    for (const auto kMaterialElement : materialsArray) {
        if (materials.size() >= kMaximumLicenseRecords) {
            return std::unexpected(Failure{
                FailureCode::LimitExceeded, indexPath.generic_string(), "license materials exceed the review limit"});
        }
        simdjson::dom::object material;
        if (const auto kError = kMaterialElement.get_object().get(material); kError) {
            return std::unexpected(invalidLicenseJson(indexPath, "license material must be an object"));
        }
        auto relativePath = requiredString(material, "path", indexPath);
        auto expectedSha256 = requiredString(material, "sha256", indexPath);
        if (!relativePath || !expectedSha256) {
            return std::unexpected(!relativePath ? relativePath.error() : expectedSha256.error());
        }
        std::int64_t expectedBytes = 0;
        if (const auto kError = material.at_key("byteSize").get_int64().get(expectedBytes);
            (kError != 0) || expectedBytes <= 0) {
            return std::unexpected(invalidLicenseJson(indexPath, "license material byteSize is invalid"));
        }
        if (!relativePath->starts_with("third_party/licenses/")) {
            return std::unexpected(Failure{
                FailureCode::InvalidPath, *relativePath, "license material must live under third_party/licenses"});
        }
        if (!seenPaths.insert(*relativePath).second) {
            return std::unexpected(
                Failure{FailureCode::OwnershipCollision, *relativePath, "license material path is duplicated"});
        }

        auto materialFile = resolveRepositoryPath(repositoryRoot, *relativePath);
        if (!materialFile) {
            return std::unexpected(materialFile.error());
        }
        std::error_code sizeError;
        const auto kActualBytes = std::filesystem::file_size(*materialFile, sizeError);
        if (sizeError || kActualBytes != static_cast<std::uintmax_t>(expectedBytes)) {
            return std::unexpected(
                Failure{FailureCode::VerificationFailed, *relativePath, "license material byte length does not match"});
        }
        auto actualSha256 = sha256File(*materialFile);
        if (!actualSha256) {
            return std::unexpected(actualSha256.error());
        }
        if (*actualSha256 != *expectedSha256) {
            return std::unexpected(
                Failure{FailureCode::VerificationFailed, *relativePath, "license material digest does not match"});
        }
        materials.push_back(LicenseMaterial{
            .path = std::move(*relativePath),
            .byteSize = kActualBytes,
            .sha256 = std::move(*actualSha256),
        });
    }
    if (materials.empty()) {
        return std::unexpected(
            Failure{FailureCode::InvalidManifest, indexPath.generic_string(), "license index lists no material"});
    }
    std::ranges::sort(materials, {}, &LicenseMaterial::path);
    return materials;
}

} // namespace

Result<LicenseReview> reviewLicenses(const std::filesystem::path& repositoryRoot) {
    auto catalogFacts = readCatalogLicenseFacts(repositoryRoot);
    if (!catalogFacts) {
        return std::unexpected(catalogFacts.error());
    }

    auto indexPath = resolveRepositoryPath(repositoryRoot, "third_party/licenses/index.json");
    if (!indexPath) {
        return std::unexpected(indexPath.error());
    }
    if (auto admission = validateJsonAdmission(*indexPath); !admission) {
        return std::unexpected(admission.error());
    }
    auto input = readBoundedFile(*indexPath);
    if (!input) {
        return std::unexpected(input.error());
    }

    simdjson::dom::parser parser;
    simdjson::dom::object indexRoot;
    if (const auto kError = parser.parse(*input).get_object().get(indexRoot); kError) {
        return std::unexpected(invalidLicenseJson(*indexPath, "license index must be a JSON object"));
    }
    std::int64_t schemaVersion = 0;
    if (const auto kError = indexRoot.at_key("schemaVersion").get_int64().get(schemaVersion);
        (kError != 0) || schemaVersion != 1) {
        return std::unexpected(invalidLicenseJson(*indexPath, "license index schemaVersion must be 1"));
    }

    auto materials = verifyMaterials(repositoryRoot, indexRoot, *indexPath);
    if (!materials) {
        return std::unexpected(materials.error());
    }
    std::set<std::string, std::less<>> materialPaths;
    for (const auto& material : *materials) {
        materialPaths.insert(material.path);
    }

    simdjson::dom::array entriesArray;
    if (const auto kError = indexRoot.at_key("entries").get_array().get(entriesArray); kError) {
        return std::unexpected(invalidLicenseJson(*indexPath, "license index lacks an entries array"));
    }

    LicenseReview review;
    review.materials = std::move(*materials);
    review.catalogEntryCount = catalogFacts->size();
    std::set<std::string, std::less<>> coveredCatalogIds;
    for (const auto kEntryElement : entriesArray) {
        if (review.entries.size() >= kMaximumLicenseRecords) {
            return std::unexpected(Failure{
                FailureCode::LimitExceeded, indexPath->generic_string(), "license entries exceed the review limit"});
        }
        simdjson::dom::object entry;
        if (const auto kError = kEntryElement.get_object().get(entry); kError) {
            return std::unexpected(invalidLicenseJson(*indexPath, "license entry must be an object"));
        }

        LicenseReviewEntry reviewEntry;
        for (const auto& [field, destination] : std::initializer_list<std::pair<std::string_view, std::string*>>{
                 {"id", &reviewEntry.licenseId},
                 {"spdxExpression", &reviewEntry.spdxExpression},
                 {"materialPath", &reviewEntry.materialPath},
                 {"sectionHeading", &reviewEntry.sectionHeading},
                 {"redistribution", &reviewEntry.redistribution},
                 {"approval", &reviewEntry.approval},
             }) {
            auto value = requiredString(entry, field, *indexPath);
            if (!value) {
                return std::unexpected(value.error());
            }
            *destination = std::move(*value);
        }
        if (!materialPaths.contains(reviewEntry.materialPath)) {
            return std::unexpected(Failure{
                FailureCode::InvalidManifest, reviewEntry.licenseId, "license entry references unindexed material"});
        }
        if (reviewEntry.approval != "approved" && reviewEntry.approval != "restricted") {
            return std::unexpected(
                Failure{FailureCode::InvalidManifest, reviewEntry.licenseId, "license approval state is unknown"});
        }
        if (reviewEntry.approval == "restricted") {
            ++review.restrictedCount;
        }

        simdjson::dom::array catalogIdsArray;
        if (const auto kError = entry.at_key("catalogIds").get_array().get(catalogIdsArray); kError) {
            return std::unexpected(invalidLicenseJson(*indexPath, "license entry lacks catalogIds"));
        }
        for (const auto kCatalogIdElement : catalogIdsArray) {
            std::string_view catalogId;
            if (const auto kError = kCatalogIdElement.get_string().get(catalogId); kError) {
                return std::unexpected(invalidLicenseJson(*indexPath, "license catalogIds must be strings"));
            }
            const auto kFacts = catalogFacts->find(catalogId);
            if (kFacts == catalogFacts->end()) {
                return std::unexpected(Failure{FailureCode::MissingInput,
                                               std::string(catalogId),
                                               "license entry references an unknown catalog ID"});
            }
            if (!coveredCatalogIds.insert(std::string(catalogId)).second) {
                return std::unexpected(Failure{FailureCode::OwnershipCollision,
                                               std::string(catalogId),
                                               "catalog ID is covered by more than one license entry"});
            }
            if (kFacts->second.spdxExpression != reviewEntry.spdxExpression ||
                kFacts->second.redistribution != reviewEntry.redistribution ||
                kFacts->second.approval != reviewEntry.approval) {
                return std::unexpected(Failure{FailureCode::VerificationFailed,
                                               std::string(catalogId),
                                               "license index disagrees with the catalog license authority"});
            }
            if (reviewEntry.advisoryPolicy.empty()) {
                reviewEntry.advisoryPolicy = kFacts->second.advisoryPolicy;
            } else if (reviewEntry.advisoryPolicy != kFacts->second.advisoryPolicy) {
                return std::unexpected(Failure{FailureCode::VerificationFailed,
                                               std::string(catalogId),
                                               "license entry spans conflicting advisory policies"});
            }
            reviewEntry.catalogIds.emplace_back(catalogId);
        }
        if (reviewEntry.catalogIds.empty()) {
            return std::unexpected(
                Failure{FailureCode::InvalidManifest, reviewEntry.licenseId, "license entry covers no catalog ID"});
        }
        std::ranges::sort(reviewEntry.catalogIds);
        review.entries.push_back(std::move(reviewEntry));
    }

    for (const auto& [catalogId, facts] : *catalogFacts) {
        if (!coveredCatalogIds.contains(catalogId)) {
            return std::unexpected(
                Failure{FailureCode::MissingInput, catalogId, "catalog entry has no license review coverage"});
        }
    }

    std::ranges::sort(review.entries, {}, &LicenseReviewEntry::licenseId);
    const auto kDuplicate = std::ranges::adjacent_find(review.entries, {}, &LicenseReviewEntry::licenseId);
    if (kDuplicate != review.entries.end()) {
        return std::unexpected(Failure{
            FailureCode::OwnershipCollision, kDuplicate->licenseId, "license index contains a duplicate entry ID"});
    }
    return review;
}

} // namespace rawframe::tool::evidence
