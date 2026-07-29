#include "dependency_authority.h"

#include "file_reader.h"
#include "path_policy.h"
#include "sha256.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <simdjson.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// The dependency closure is built with its upstream defaults rather than the
// ADR-0008 first-party flags, so simdjson's own objects carry exception and RTTI
// support. What matters is the boundary, not the archive: simdjson derives
// `SIMDJSON_EXCEPTIONS` from the translation unit that includes it, and this one
// compiles without exceptions, so the throwing accessors are not declared here
// at all and every result must be consumed through its error code. That is the
// property this file depends on, so it is checked by the compiler instead of
// being argued in a document.
static_assert(SIMDJSON_EXCEPTIONS == 0,
              "first-party translation units must see the error-code simdjson API, never the throwing one");

namespace rawframe::tool::evidence {

namespace {

struct LicensePolicy {
    std::string spdxExpression;
    std::string redistribution;
    std::string approval;
};

struct AuthoritySets {
    std::set<std::string, std::less<>> catalogIds;
    std::set<std::string, std::less<>> artifactIds;
    std::set<std::string, std::less<>> managedToolIds;
    std::set<std::string, std::less<>> licenseIds;
    std::map<std::string, LicensePolicy, std::less<>> catalogLicenses;
    std::vector<std::pair<std::string, std::string>> artifactVerificationReferences;
};

std::string lowercase(std::string_view value) {
    std::string result(value);
    std::ranges::transform(result, result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

Result<simdjson::dom::object>
loadObject(const std::filesystem::path& path, simdjson::dom::parser& parser, simdjson::padded_string& storage) {
    auto input = readBoundedFile(path);
    if (!input) {
        return std::unexpected(input.error());
    }
    storage = std::move(*input);
    simdjson::dom::element element;
    if (const auto kError = parser.parse(storage).get(element); kError) {
        return std::unexpected(
            Failure{FailureCode::InvalidJson, path.generic_string(), simdjson::error_message(kError)});
    }
    simdjson::dom::object object;
    if (const auto kError = element.get_object().get(object); kError) {
        return std::unexpected(
            Failure{FailureCode::InvalidJson, path.generic_string(), "authority root must be an object"});
    }
    return object;
}

Result<std::string>
stringField(simdjson::dom::object object, std::string_view field, const std::filesystem::path& path) {
    std::string_view value;
    if (const auto kError = object.at_key(field).get_string().get(value); kError) {
        return std::unexpected(Failure{
            FailureCode::InvalidJson, path.generic_string(), std::string("invalid field: ") + std::string(field)});
    }
    return std::string(value);
}

Status insertUnique(std::set<std::string, std::less<>>& values,
                    std::string_view value,
                    const std::filesystem::path& path,
                    std::string_view kind) {
    if (!values.insert(lowercase(value)).second) {
        return std::unexpected(
            Failure{FailureCode::OwnershipCollision, path.generic_string(), std::string(kind) + " ID collides"});
    }
    return {};
}

Status loadCatalog(const std::filesystem::path& repositoryRoot, AuthoritySets& sets) {
    const auto kPath = repositoryRoot / "third_party/catalog.json";
    simdjson::dom::parser parser;
    simdjson::padded_string storage;
    auto root = loadObject(kPath, parser, storage);
    if (!root) {
        return std::unexpected(root.error());
    }
    simdjson::dom::array entries;
    if (const auto kError = (*root).at_key("entries").get_array().get(entries); kError) {
        return std::unexpected(
            Failure{FailureCode::InvalidJson, kPath.generic_string(), "catalog entries are invalid"});
    }
    for (const auto kElement : entries) {
        simdjson::dom::object entry;
        if (kElement.get_object().get(entry) != 0) {
            return std::unexpected(
                Failure{FailureCode::InvalidJson, kPath.generic_string(), "catalog entry must be an object"});
        }
        auto id = stringField(entry, "id", kPath);
        if (!id) {
            return std::unexpected(id.error());
        }
        if (auto status = insertUnique(sets.catalogIds, *id, kPath, "catalog"); !status) {
            return status;
        }

        simdjson::dom::object license;
        if (entry.at_key("license").get_object().get(license) != 0) {
            return std::unexpected(Failure{FailureCode::InvalidJson, *id, "catalog license policy must be an object"});
        }
        auto spdxExpression = stringField(license, "spdxExpression", kPath);
        if (!spdxExpression) {
            return std::unexpected(spdxExpression.error());
        }
        auto redistribution = stringField(license, "redistribution", kPath);
        if (!redistribution) {
            return std::unexpected(redistribution.error());
        }
        auto approval = stringField(license, "approval", kPath);
        if (!approval) {
            return std::unexpected(approval.error());
        }
        sets.catalogLicenses.emplace(
            lowercase(*id),
            LicensePolicy{std::move(*spdxExpression), std::move(*redistribution), std::move(*approval)});

        simdjson::dom::object provider;
        if (entry.at_key("provider").get_object().get(provider) != 0) {
            return std::unexpected(Failure{FailureCode::InvalidJson, *id, "provider must be one closed object"});
        }
        auto type = stringField(provider, "type", kPath);
        auto reference = stringField(provider, "reference", kPath);
        if (!type || !reference || reference->empty()) {
            return std::unexpected(Failure{FailureCode::InvalidManifest, *id, "provider type/reference is incomplete"});
        }
    }
    if (sets.catalogIds.size() != 16U) {
        return std::unexpected(Failure{FailureCode::InvalidManifest,
                                       kPath.generic_string(),
                                       "TASK-0001 catalog must contain exactly 16 admitted entries"});
    }
    return {};
}

Status loadLicenses(const std::filesystem::path& repositoryRoot, AuthoritySets& sets) {
    const auto kPath = repositoryRoot / "third_party/licenses/index.json";
    simdjson::dom::parser parser;
    simdjson::padded_string storage;
    auto root = loadObject(kPath, parser, storage);
    if (!root) {
        return std::unexpected(root.error());
    }
    std::int64_t schemaVersion = 0;
    if (((*root).at_key("schemaVersion").get_int64().get(schemaVersion) != 0) || schemaVersion != 1) {
        return std::unexpected(
            Failure{FailureCode::InvalidManifest, kPath.generic_string(), "license index schemaVersion must be 1"});
    }
    simdjson::dom::array materials;
    if (((*root).at_key("materials").get_array().get(materials) != 0) || materials.size() != 5U) {
        return std::unexpected(Failure{FailureCode::InvalidManifest,
                                       kPath.generic_string(),
                                       "license index must contain exactly five offline material files"});
    }
    std::map<std::string, std::string, std::less<>> materialContents;
    for (const auto kElement : materials) {
        simdjson::dom::object material;
        if (kElement.get_object().get(material) != 0) {
            return std::unexpected(
                Failure{FailureCode::InvalidJson, kPath.generic_string(), "license material must be an object"});
        }
        auto relative = stringField(material, "path", kPath);
        auto expectedDigest = stringField(material, "sha256", kPath);
        std::uint64_t expectedBytes = 0;
        if (!relative || !expectedDigest || (material.at_key("byteSize").get_uint64().get(expectedBytes) != 0) ||
            !relative->starts_with("third_party/licenses/") || relative->contains('\\')) {
            return std::unexpected(
                Failure{FailureCode::InvalidManifest, kPath.generic_string(), "license material identity is invalid"});
        }
        auto resolved = resolveRepositoryPath(repositoryRoot, *relative);
        if (!resolved) {
            return std::unexpected(resolved.error());
        }
        std::error_code sizeError;
        const auto kObservedBytes = std::filesystem::file_size(*resolved, sizeError);
        auto observedDigest = sha256File(*resolved);
        auto content = readBoundedFile(*resolved);
        if (sizeError || !observedDigest || !content || kObservedBytes != expectedBytes ||
            *observedDigest != *expectedDigest || !materialContents.emplace(*relative, std::string(*content)).second) {
            return std::unexpected(
                Failure{FailureCode::VerificationFailed, *relative, "offline license material identity mismatch"});
        }
    }

    simdjson::dom::array entries;
    if (((*root).at_key("entries").get_array().get(entries) != 0) || entries.size() != 16U) {
        return std::unexpected(Failure{
            FailureCode::InvalidManifest, kPath.generic_string(), "license index must contain exactly 16 policies"});
    }
    std::set<std::string, std::less<>> coveredCatalogs;
    for (const auto kElement : entries) {
        simdjson::dom::object entry;
        if (kElement.get_object().get(entry) != 0) {
            return std::unexpected(
                Failure{FailureCode::InvalidJson, kPath.generic_string(), "license entry must be an object"});
        }
        auto id = stringField(entry, "id", kPath);
        auto spdxExpression = stringField(entry, "spdxExpression", kPath);
        auto materialPath = stringField(entry, "materialPath", kPath);
        auto sectionHeading = stringField(entry, "sectionHeading", kPath);
        auto redistribution = stringField(entry, "redistribution", kPath);
        auto approval = stringField(entry, "approval", kPath);
        if (!id || !spdxExpression || !materialPath || !sectionHeading || !redistribution || !approval) {
            return std::unexpected(
                Failure{FailureCode::InvalidJson, kPath.generic_string(), "license entry fields are incomplete"});
        }
        if (auto status = insertUnique(sets.licenseIds, *id, kPath, "license"); !status) {
            return status;
        }
        const auto kMaterial = materialContents.find(*materialPath);
        if (kMaterial == materialContents.end() || !kMaterial->second.contains("## " + *sectionHeading)) {
            return std::unexpected(Failure{FailureCode::InvalidManifest, *id, "license material section is absent"});
        }
        simdjson::dom::array catalogIds;
        if ((entry.at_key("catalogIds").get_array().get(catalogIds) != 0) || catalogIds.size() == 0U) {
            return std::unexpected(Failure{FailureCode::InvalidJson, *id, "license catalog mapping is invalid"});
        }
        for (const auto kCatalogElement : catalogIds) {
            std::string_view catalogId;
            if (kCatalogElement.get_string().get(catalogId) != 0) {
                return std::unexpected(Failure{FailureCode::InvalidJson, *id, "license catalog ID must be a string"});
            }
            const auto kPolicy = sets.catalogLicenses.find(lowercase(catalogId));
            if (kPolicy == sets.catalogLicenses.end() || !coveredCatalogs.insert(lowercase(catalogId)).second ||
                kPolicy->second.spdxExpression != *spdxExpression ||
                kPolicy->second.redistribution != *redistribution || kPolicy->second.approval != *approval) {
                return std::unexpected(
                    Failure{FailureCode::InvalidManifest, *id, "license policy differs from its catalog authority"});
            }
        }
    }
    if (coveredCatalogs != sets.catalogIds) {
        return std::unexpected(Failure{FailureCode::InvalidManifest,
                                       kPath.generic_string(),
                                       "license index does not cover every catalog entry exactly once"});
    }
    return {};
}

Status loadArtifacts(const std::filesystem::path& repositoryRoot, AuthoritySets& sets) {
    const auto kPath = repositoryRoot / "third_party/artifacts.lock.json";
    simdjson::dom::parser parser;
    simdjson::padded_string storage;
    auto root = loadObject(kPath, parser, storage);
    if (!root) {
        return std::unexpected(root.error());
    }
    simdjson::dom::array artifacts;
    if ((*root).at_key("artifacts").get_array().get(artifacts) != 0) {
        return std::unexpected(Failure{FailureCode::InvalidJson, kPath.generic_string(), "artifact list is invalid"});
    }
    for (const auto kElement : artifacts) {
        simdjson::dom::object artifact;
        if (kElement.get_object().get(artifact) != 0) {
            return std::unexpected(
                Failure{FailureCode::InvalidJson, kPath.generic_string(), "artifact entry must be an object"});
        }
        auto id = stringField(artifact, "id", kPath);
        if (!id) {
            return std::unexpected(id.error());
        }
        auto catalogId = stringField(artifact, "catalogId", kPath);
        if (!catalogId) {
            return std::unexpected(catalogId.error());
        }
        auto licenseReference = stringField(artifact, "licenseReference", kPath);
        if (!licenseReference) {
            return std::unexpected(licenseReference.error());
        }
        if (!sets.catalogIds.contains(lowercase(*catalogId))) {
            return std::unexpected(
                Failure{FailureCode::InvalidManifest, *id, "artifact references an unknown catalog ID"});
        }
        if (auto status = insertUnique(sets.artifactIds, *id, kPath, "artifact"); !status) {
            return status;
        }
        if (!sets.licenseIds.contains(lowercase(*licenseReference))) {
            return std::unexpected(
                Failure{FailureCode::InvalidManifest, *id, "artifact references unknown offline license material"});
        }
        simdjson::dom::object signature;
        if (artifact.at_key("signature").get_object().get(signature) != 0) {
            return std::unexpected(
                Failure{FailureCode::InvalidJson, *id, "artifact signature policy must be an object"});
        }
        bool signatureRequired = false;
        if (signature.at_key("required").get_bool().get(signatureRequired) != 0) {
            return std::unexpected(
                Failure{FailureCode::InvalidJson, *id, "artifact signature required flag is invalid"});
        }
        auto signatureScheme = stringField(signature, "scheme", kPath);
        if (!signatureScheme || (signatureRequired && *signatureScheme == "none") ||
            (!signatureRequired && *signatureScheme != "none")) {
            return std::unexpected(Failure{
                FailureCode::InvalidManifest, *id, "artifact signature required/scheme contract is inconsistent"});
        }
        std::set<std::string, std::less<>> localReferences;
        auto referencesElement = signature.at_key("verificationArtifactIds");
        if (referencesElement.error() == 0) {
            simdjson::dom::array references;
            if (referencesElement.get_array().get(references) != 0) {
                return std::unexpected(
                    Failure{FailureCode::InvalidJson, *id, "artifact verification reference list is invalid"});
            }
            for (const auto kReferenceElement : references) {
                std::string_view reference;
                if ((kReferenceElement.get_string().get(reference) != 0) ||
                    !localReferences.insert(lowercase(reference)).second) {
                    return std::unexpected(Failure{
                        FailureCode::InvalidManifest, *id, "artifact verification reference is invalid or duplicated"});
                }
                sets.artifactVerificationReferences.emplace_back(*id, std::string(reference));
            }
        } else if (referencesElement.error() != simdjson::NO_SUCH_FIELD) {
            return std::unexpected(
                Failure{FailureCode::InvalidJson, *id, "artifact verification references cannot be read"});
        }
        if (*signatureScheme == "gpg_sigstore" && (!signatureRequired || localReferences.size() != 4U)) {
            return std::unexpected(Failure{
                FailureCode::InvalidManifest, *id, "composite LLVM verification requires exactly four authorities"});
        }
        simdjson::dom::object archive;
        if (artifact.at_key("archive").get_object().get(archive) != 0) {
            return std::unexpected(
                Failure{FailureCode::InvalidJson, *id, "artifact archive contract must be an object"});
        }
        const bool kHasRoot = archive.at_key("root").error() == 0;
        const bool kHasRoots = archive.at_key("roots").error() == 0;
        const bool kHasRootless = archive.at_key("rootless").error() == 0;
        if ((kHasRoot ? 1 : 0) + (kHasRoots ? 1 : 0) + (kHasRootless ? 1 : 0) != 1) {
            return std::unexpected(Failure{FailureCode::InvalidManifest,
                                           *id,
                                           "artifact archive must declare exactly one of root, roots, or rootless"});
        }
        if (kHasRoots) {
            simdjson::dom::array roots;
            if ((archive.at_key("roots").get_array().get(roots) != 0) || roots.size() < 2U || roots.size() > 32U) {
                return std::unexpected(
                    Failure{FailureCode::InvalidManifest, *id, "artifact archive root set is not closed"});
            }
        }
        if (kHasRootless) {
            simdjson::dom::object rootless;
            if (archive.at_key("rootless").get_object().get(rootless) != 0) {
                return std::unexpected(
                    Failure{FailureCode::InvalidJson, *id, "rootless archive contract must be an object"});
            }
            std::int64_t entryCount = 0;
            std::int64_t topLevelDirectories = -1;
            std::int64_t topLevelFiles = -1;
            if ((rootless.at_key("entryCount").get_int64().get(entryCount) != 0) ||
                (rootless.at_key("topLevelDirectories").get_int64().get(topLevelDirectories) != 0) ||
                (rootless.at_key("topLevelFiles").get_int64().get(topLevelFiles) != 0) || entryCount < 1 ||
                entryCount > 300000 || topLevelDirectories < 0 || topLevelFiles < 0 ||
                topLevelDirectories + topLevelFiles < 1 || topLevelDirectories + topLevelFiles > entryCount) {
                return std::unexpected(
                    Failure{FailureCode::InvalidManifest, *id, "rootless archive shape contract is invalid"});
            }
        }
    }
    if (sets.artifactIds.size() != 50U) {
        return std::unexpected(Failure{FailureCode::InvalidManifest,
                                       kPath.generic_string(),
                                       "TASK-0001 artifact lock must contain exactly 50 admitted inputs"});
    }
    for (const auto& [owner, reference] : sets.artifactVerificationReferences) {
        if (!sets.artifactIds.contains(lowercase(reference))) {
            return std::unexpected(Failure{
                FailureCode::InvalidManifest, owner, "artifact verification authority is absent from the lock"});
        }
    }
    return {};
}

Status loadToolchain(const std::filesystem::path& repositoryRoot, AuthoritySets& sets) {
    const auto kPath = repositoryRoot / "third_party/toolchain.lock.json";
    simdjson::dom::parser parser;
    simdjson::padded_string storage;
    auto root = loadObject(kPath, parser, storage);
    if (!root) {
        return std::unexpected(root.error());
    }
    simdjson::dom::object bootstrap;
    if ((*root).at_key("bootstrap").get_object().get(bootstrap) != 0) {
        return std::unexpected(
            Failure{FailureCode::InvalidJson, kPath.generic_string(), "bootstrap verifier contract is invalid"});
    }
    std::int64_t verifierContractVersion = 0;
    if ((bootstrap.at_key("verifierContractVersion").get_int64().get(verifierContractVersion) != 0) ||
        verifierContractVersion != 1) {
        return std::unexpected(Failure{
            FailureCode::InvalidManifest, kPath.generic_string(), "bootstrap verifier contract version must be 1"});
    }
    simdjson::dom::array verifierArtifacts;
    if (bootstrap.at_key("verifierArtifactIds").get_array().get(verifierArtifacts) != 0) {
        return std::unexpected(
            Failure{FailureCode::InvalidJson, kPath.generic_string(), "bootstrap verifier artifact list is invalid"});
    }
    std::set<std::string, std::less<>> verifierIds;
    for (const auto kVerifierElement : verifierArtifacts) {
        std::string_view verifierId;
        if ((kVerifierElement.get_string().get(verifierId) != 0) || !sets.artifactIds.contains(lowercase(verifierId)) ||
            !verifierIds.insert(lowercase(verifierId)).second) {
            return std::unexpected(Failure{FailureCode::InvalidManifest,
                                           kPath.generic_string(),
                                           "bootstrap verifier artifact is missing or duplicated"});
        }
    }
    if (verifierIds.size() != 18U) {
        return std::unexpected(Failure{FailureCode::InvalidManifest,
                                       kPath.generic_string(),
                                       "bootstrap verifier contract must contain exactly 18 artifacts"});
    }
    simdjson::dom::array tools;
    if ((*root).at_key("managedTools").get_array().get(tools) != 0) {
        return std::unexpected(
            Failure{FailureCode::InvalidJson, kPath.generic_string(), "managed tool list is invalid"});
    }
    for (const auto kElement : tools) {
        simdjson::dom::object tool;
        if (kElement.get_object().get(tool) != 0) {
            return std::unexpected(
                Failure{FailureCode::InvalidJson, kPath.generic_string(), "managed tool must be an object"});
        }
        auto id = stringField(tool, "id", kPath);
        if (!id) {
            return std::unexpected(id.error());
        }
        if (!sets.catalogIds.contains(lowercase(*id))) {
            return std::unexpected(Failure{FailureCode::InvalidManifest, *id, "managed tool is absent from catalog"});
        }
        if (auto status = insertUnique(sets.managedToolIds, *id, kPath, "managed tool"); !status) {
            return status;
        }
        simdjson::dom::array artifactIds;
        if (tool.at_key("artifactIds").get_array().get(artifactIds) != 0) {
            return std::unexpected(Failure{FailureCode::InvalidJson, *id, "managed tool artifact list is invalid"});
        }
        for (const auto kArtifactElement : artifactIds) {
            std::string_view artifactId;
            if ((kArtifactElement.get_string().get(artifactId) != 0) ||
                !sets.artifactIds.contains(lowercase(artifactId))) {
                return std::unexpected(
                    Failure{FailureCode::InvalidManifest, *id, "managed tool references an unknown artifact"});
            }
        }
    }
    if (sets.managedToolIds.size() != 11U) {
        return std::unexpected(Failure{FailureCode::InvalidManifest,
                                       kPath.generic_string(),
                                       "TASK-0001 toolchain must contain exactly eleven managed tools"});
    }
    simdjson::dom::array installedSdks;
    if (((*root).at_key("installedSdks").get_array().get(installedSdks) != 0) || installedSdks.size() != 1U) {
        return std::unexpected(Failure{FailureCode::InvalidManifest,
                                       kPath.generic_string(),
                                       "TASK-0001 requires exactly one installed SDK contract"});
    }
    simdjson::dom::object windowsSdk;
    if (installedSdks.at(0).get_object().get(windowsSdk) != 0) {
        return std::unexpected(
            Failure{FailureCode::InvalidJson, kPath.generic_string(), "installed Windows SDK contract is invalid"});
    }
    auto sdkId = stringField(windowsSdk, "id", kPath);
    simdjson::dom::array verificationExecutables;
    if (!sdkId || *sdkId != "sdk.windows_11" ||
        (windowsSdk.at_key("verificationExecutables").get_array().get(verificationExecutables) != 0) ||
        verificationExecutables.size() != 1U) {
        return std::unexpected(Failure{FailureCode::InvalidManifest,
                                       kPath.generic_string(),
                                       "Windows SDK verification executable contract is incomplete"});
    }
    simdjson::dom::object signTool;
    if (verificationExecutables.at(0).get_object().get(signTool) != 0) {
        return std::unexpected(
            Failure{FailureCode::InvalidJson, kPath.generic_string(), "Windows SDK SignTool contract is invalid"});
    }
    auto signToolId = stringField(signTool, "id", kPath);
    auto signToolPath = stringField(signTool, "absolutePath", kPath);
    auto signToolVersion = stringField(signTool, "version", kPath);
    auto signToolDigest = stringField(signTool, "binarySha256", kPath);
    auto signToolCapability = stringField(signTool, "capability", kPath);
    std::uint64_t signToolBytes = 0;
    if (!signToolId || !signToolPath || !signToolVersion || !signToolDigest || !signToolCapability ||
        (signTool.at_key("byteSize").get_uint64().get(signToolBytes) != 0) ||
        *signToolId != "tool.windows_sdk.signtool" ||
        *signToolPath != "C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/signtool.exe" ||
        *signToolVersion != "10.0.26100.8249" || signToolBytes != 543144U ||
        *signToolDigest != "e7b517a6a2828af2d1fba3da60ae1e322a95141bfae192622725329630caa2b3" ||
        *signToolCapability != "capability.authenticode_verify") {
        return std::unexpected(Failure{FailureCode::InvalidManifest,
                                       kPath.generic_string(),
                                       "Windows SDK SignTool identity differs from TASK-0001"});
    }
    return {};
}

} // namespace

Status validateDependencyAuthorities(const std::filesystem::path& repositoryRoot,
                                     const RepositorySnapshot& repository) {
    AuthoritySets sets;
    if (auto status = loadCatalog(repositoryRoot, sets); !status) {
        return status;
    }
    if (auto status = loadLicenses(repositoryRoot, sets); !status) {
        return status;
    }
    if (auto status = loadArtifacts(repositoryRoot, sets); !status) {
        return status;
    }
    if (auto status = loadToolchain(repositoryRoot, sets); !status) {
        return status;
    }

    for (const auto& tool : repository.tools) {
        for (const auto& dependency : tool.thirdPartyDependencies) {
            if (!sets.catalogIds.contains(lowercase(dependency))) {
                return std::unexpected(Failure{
                    FailureCode::InvalidManifest, tool.id, "tool references an unknown third-party dependency"});
            }
        }
        for (const auto& dependency : tool.managedToolDependencies) {
            if (!sets.managedToolIds.contains(lowercase(dependency))) {
                return std::unexpected(
                    Failure{FailureCode::InvalidManifest, tool.id, "tool references an unknown managed tool"});
            }
        }
    }
    return {};
}

} // namespace rawframe::tool::evidence
