#include "repository_validator.h"

#include "dependency_authority.h"
#include "descriptor.h"
#include "file_reader.h"
#include "file_security.h"
#include "path_policy.h"
#include "schema_oracle.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <set>
#include <simdjson.h>
#include <string_view>
#include <utility>

namespace rawframe::tool::evidence {

namespace {

Failure invalidJson(const std::filesystem::path& path, std::string_view context, simdjson::error_code error) {
    return Failure{
        FailureCode::InvalidJson,
        path.generic_string(),
        std::string(context) + ": " + simdjson::error_message(error),
    };
}

Result<simdjson::dom::object>
parseObject(simdjson::dom::parser& parser, simdjson::padded_string& input, const std::filesystem::path& path) {
    simdjson::dom::element element;
    if (const auto kError = parser.parse(input).get(element); kError) {
        return std::unexpected(invalidJson(path, "failed to parse JSON", kError));
    }

    simdjson::dom::object object;
    if (const auto kError = element.get_object().get(object); kError) {
        return std::unexpected(invalidJson(path, "top-level value must be an object", kError));
    }
    return object;
}

Result<std::string>
requiredString(simdjson::dom::object object, std::string_view key, const std::filesystem::path& path) {
    std::string_view value;
    if (const auto kError = object.at_key(key).get_string().get(value); kError) {
        return std::unexpected(
            invalidJson(path, std::string("missing or invalid string field ") + std::string(key), kError));
    }
    return std::string(value);
}

Result<std::vector<std::string>> requiredStringArray(simdjson::dom::object object,
                                                     std::string_view key,
                                                     const std::filesystem::path& path,
                                                     bool allowEmpty) {
    simdjson::dom::array array;
    if (const auto kError = object.at_key(key).get_array().get(array); kError) {
        return std::unexpected(
            invalidJson(path, std::string("missing or invalid array field ") + std::string(key), kError));
    }

    std::vector<std::string> values;
    std::set<std::string, std::less<>> uniqueValues;
    for (const auto kElement : array) {
        if (values.size() >= 4'096) {
            return std::unexpected(
                Failure{FailureCode::LimitExceeded, path.generic_string(), "array exceeds 4096 entries"});
        }
        std::string_view value;
        if (const auto kError = kElement.get_string().get(value); kError) {
            return std::unexpected(invalidJson(path, std::string("non-string entry in ") + std::string(key), kError));
        }
        std::string owned(value);
        if (!uniqueValues.insert(owned).second) {
            return std::unexpected(
                Failure{FailureCode::InvalidManifest, path.generic_string(), "array contains a duplicate value"});
        }
        values.emplace_back(std::move(owned));
    }
    if (!allowEmpty && values.empty()) {
        return std::unexpected(Failure{FailureCode::InvalidManifest, path.generic_string(), "required array is empty"});
    }
    if (!std::ranges::is_sorted(values)) {
        return std::unexpected(Failure{
            FailureCode::InvalidManifest, path.generic_string(), "set-like array is not deterministically sorted"});
    }
    return values;
}

Status validateDistribution(simdjson::dom::object root, const std::filesystem::path& path) {
    simdjson::dom::object distribution;
    if (const auto kError = root.at_key("distribution").get_object().get(distribution); kError) {
        return std::unexpected(invalidJson(path, "missing distribution object", kError));
    }

    bool repositoryOnly = false;
    if (const auto kError = distribution.at_key("repositoryOnly").get_bool().get(repositoryOnly);
        (kError != 0) || !repositoryOnly) {
        return std::unexpected(
            Failure{FailureCode::InvalidManifest, path.generic_string(), "repositoryOnly must be true"});
    }
    for (const std::string_view kField : {"shippingClosure", "sdkExposure", "targetRoot"}) {
        auto value = requiredString(distribution, kField, path);
        if (!value) {
            return std::unexpected(value.error());
        }
        if (*value != "forbidden") {
            return std::unexpected(Failure{
                FailureCode::InvalidManifest, path.generic_string(), std::string(kField) + " must be forbidden"});
        }
    }
    return {};
}

Result<ToolInfo> validateToolManifest(const std::filesystem::path& repositoryRoot,
                                      const std::filesystem::path& manifestPath,
                                      std::string manifestRelativePath) {
    if (auto shape = validateJsonShape(repositoryRoot, repositoryRoot / "schemas/tool.schema.json", manifestPath);
        !shape) {
        return std::unexpected(shape.error());
    }
    auto input = readBoundedFile(manifestPath);
    if (!input) {
        return std::unexpected(input.error());
    }

    simdjson::dom::parser parser;
    auto rootResult = parseObject(parser, *input, manifestPath);
    if (!rootResult) {
        return std::unexpected(rootResult.error());
    }
    const auto kRoot = *rootResult;

    auto schema = requiredString(kRoot, "$schema", manifestPath);
    auto id = requiredString(kRoot, "id", manifestPath);
    // The manifest is the declared ownership authority for everything beneath the
    // tool root. STD-0001's ownership review has no other source of truth, so it
    // is read here rather than restated as a constant by any consumer.
    auto owner = requiredString(kRoot, "owner", manifestPath);
    if (!schema || !id || !owner) {
        if (!schema) {
            return std::unexpected(schema.error());
        }
        return std::unexpected(!id ? id.error() : owner.error());
    }
    if (*schema != "../../schemas/tool.schema.json" || !id->starts_with("rawframe.tool.")) {
        return std::unexpected(
            Failure{FailureCode::InvalidManifest, manifestPath.generic_string(), "tool schema or ID is invalid"});
    }

    std::int64_t schemaVersion = 0;
    if (const auto kError = kRoot.at_key("schemaVersion").get_int64().get(schemaVersion);
        (kError != 0) || schemaVersion != 1) {
        return std::unexpected(
            Failure{FailureCode::InvalidManifest, manifestPath.generic_string(), "tool schemaVersion must be 1"});
    }

    simdjson::dom::object implementation;
    if (const auto kError = kRoot.at_key("implementation").get_object().get(implementation); kError) {
        return std::unexpected(invalidJson(manifestPath, "missing implementation object", kError));
    }
    auto language = requiredString(implementation, "language", manifestPath);
    auto dialect = requiredString(implementation, "dialect", manifestPath);
    auto buildSystem = requiredString(implementation, "buildSystem", manifestPath);
    auto target = requiredString(implementation, "cmakeTarget", manifestPath);
    auto exceptions = requiredString(implementation, "exceptions", manifestPath);
    auto rtti = requiredString(implementation, "rtti", manifestPath);
    if (!language || !dialect || !buildSystem || !target || !exceptions || !rtti) {
        return std::unexpected(Failure{
            FailureCode::InvalidManifest, manifestPath.generic_string(), "implementation fields are incomplete"});
    }
    if (*language != "cpp" || *dialect != "c++23" || *buildSystem != "cmake" || *exceptions != "disabled" ||
        *rtti != "disabled") {
        return std::unexpected(Failure{FailureCode::InvalidManifest,
                                       manifestPath.generic_string(),
                                       "implementation policy does not match C++23/no-exception/no-RTTI"});
    }

    simdjson::dom::object dependencies;
    if (const auto kError = kRoot.at_key("dependencies").get_object().get(dependencies); kError) {
        return std::unexpected(invalidJson(manifestPath, "missing dependencies object", kError));
    }
    auto tools = requiredStringArray(dependencies, "tools", manifestPath, true);
    auto modules = requiredStringArray(dependencies, "modules", manifestPath, true);
    auto thirdParty = requiredStringArray(dependencies, "thirdParty", manifestPath, true);
    auto managedTools = requiredStringArray(dependencies, "managedTools", manifestPath, true);
    if (!tools || !modules || !thirdParty || !managedTools) {
        return std::unexpected(
            Failure{FailureCode::InvalidManifest, manifestPath.generic_string(), "dependency arrays are invalid"});
    }
    if (!modules->empty()) {
        return std::unexpected(Failure{FailureCode::InvalidManifest,
                                       manifestPath.generic_string(),
                                       "TASK-0001 repository tool cannot depend on a production module"});
    }
    if (auto status = validateDistribution(kRoot, manifestPath); !status) {
        return std::unexpected(status.error());
    }

    return ToolInfo{
        .id = std::move(*id),
        .manifestPath = std::move(manifestRelativePath),
        .owner = std::move(*owner),
        .cmakeTarget = std::move(*target),
        .thirdPartyDependencies = std::move(*thirdParty),
        .managedToolDependencies = std::move(*managedTools),
    };
}

// Membership is proven exactly as tool membership is: the index names a path,
// the path resolves inside the repository, it is an ordinary file rather than a
// link, its declared class and media type agree, and no two entries own the
// same bytes. A second set of proofs for the same property would be a second
// authority for it.
Result<std::vector<EvidenceAuthorityInfo>> readAuthorities(const std::filesystem::path& repositoryRoot,
                                                           const std::filesystem::path& indexPath) {
    auto input = readBoundedFile(indexPath);
    if (!input) {
        return std::unexpected(input.error());
    }
    simdjson::dom::parser parser;
    auto indexObject = parseObject(parser, *input, indexPath);
    if (!indexObject) {
        return std::unexpected(indexObject.error());
    }

    simdjson::dom::array entries;
    if (const auto kError = (*indexObject).at_key("authorities").get_array().get(entries); kError) {
        return std::unexpected(invalidJson(indexPath, "missing or invalid array field authorities", kError));
    }
    if (entries.size() > 256) {
        return std::unexpected(
            Failure{FailureCode::LimitExceeded, "evidence/evidence.json", "the index lists more than 256 authorities"});
    }

    std::vector<EvidenceAuthorityInfo> authorities;
    std::set<std::string, std::less<>> ownedPaths;
    for (auto element : entries) {
        simdjson::dom::object entry;
        if (const auto kError = element.get_object().get(entry); kError) {
            return std::unexpected(invalidJson(indexPath, "an authority entry is not an object", kError));
        }
        auto authorityClass = requiredString(entry, "authorityClass", indexPath);
        if (!authorityClass) {
            return std::unexpected(authorityClass.error());
        }
        auto relativePath = requiredString(entry, "path", indexPath);
        if (!relativePath) {
            return std::unexpected(relativePath.error());
        }
        auto mediaType = requiredString(entry, "mediaType", indexPath);
        if (!mediaType) {
            return std::unexpected(mediaType.error());
        }

        // The class and the media type are two statements of the same fact, so
        // they are cross-checked rather than one being derived from the other.
        std::string_view expected;
        if (*authorityClass == "metric_registry") {
            expected = kMetricRegistryMediaType;
        } else if (*authorityClass == "evaluation_policy") {
            expected = kEvaluationPolicyMediaType;
        }
        if (expected.empty()) {
            return std::unexpected(
                Failure{FailureCode::InvalidManifest, *relativePath, "unknown evidence authority class"});
        }
        if (*mediaType != expected) {
            return std::unexpected(Failure{
                FailureCode::InvalidManifest, *relativePath, "media type disagrees with the declared authority class"});
        }

        auto resolved = resolveRepositoryPath(repositoryRoot, *relativePath);
        if (!resolved) {
            return std::unexpected(resolved.error());
        }
        auto kind = classifyPath(repositoryRoot / std::filesystem::path(*relativePath));
        if (!kind) {
            return std::unexpected(kind.error());
        }
        if (*kind != FileKind::Regular) {
            return std::unexpected(Failure{FailureCode::InvalidPath,
                                           *relativePath,
                                           std::string("the evidence authority is a ") + fileKindName(*kind)});
        }
        if (!ownedPaths.insert(portableLowercasePath(*relativePath)).second) {
            return std::unexpected(
                Failure{FailureCode::OwnershipCollision, *relativePath, "the index lists this authority twice"});
        }
        authorities.emplace_back(EvidenceAuthorityInfo{
            .authorityClass = std::move(*authorityClass),
            .path = std::move(*relativePath),
            .mediaType = std::move(*mediaType),
        });
    }
    std::ranges::sort(authorities, {}, &EvidenceAuthorityInfo::path);
    return authorities;
}

// The counterpart of rejectUnlistedToolManifests. An authority that exists but
// is not named is the one failure a membership model cannot report by reading
// its own list, so it is proven by looking at the tree and refusing what the
// list does not claim.
Status rejectUnlisted(const std::filesystem::path& repositoryRoot,
                      std::string_view indexRelativePath,
                      const std::vector<EvidenceAuthorityInfo>& authorities) {
    const auto kEvidenceRoot = repositoryRoot / "evidence";
    std::error_code error;
    if (!std::filesystem::exists(kEvidenceRoot, error)) {
        return {};
    }

    std::set<std::string, std::less<>> listed;
    listed.insert(portableLowercasePath(std::string(indexRelativePath)));
    for (const auto& authority : authorities) {
        listed.insert(portableLowercasePath(authority.path));
    }

    std::size_t candidates = 0;
    for (std::filesystem::recursive_directory_iterator iterator(kEvidenceRoot, error), end; iterator != end;
         iterator.increment(error)) {
        if (error) {
            return std::unexpected(
                Failure{FailureCode::IoFailure, "evidence", "failed while auditing maintained evidence"});
        }
        if (iterator->is_symlink(error)) {
            return std::unexpected(Failure{
                FailureCode::InvalidPath,
                std::filesystem::relative(iterator->path(), repositoryRoot, error).generic_string(),
                "maintained evidence contains a link",
            });
        }
        if (!iterator->is_regular_file(error)) {
            continue;
        }
        if (++candidates > 256) {
            return std::unexpected(
                Failure{FailureCode::LimitExceeded, "evidence", "maintained evidence exceeds 256 files"});
        }
        const auto kRelative = std::filesystem::relative(iterator->path(), repositoryRoot, error).generic_string();
        if (error || !listed.contains(portableLowercasePath(kRelative))) {
            return std::unexpected(Failure{
                FailureCode::InvalidManifest, kRelative, "evidence authority is not listed in the evidence index"});
        }
    }
    return {};
}

Status rejectUnlistedToolManifests(const RepositorySnapshot& snapshot) {
    const auto kToolsRoot = snapshot.root / "tools";
    std::error_code error;
    if (!std::filesystem::exists(kToolsRoot, error)) {
        return {};
    }

    std::set<std::string, std::less<>> listed;
    for (const auto& tool : snapshot.tools) {
        listed.insert(portableLowercasePath(tool.manifestPath));
    }

    std::size_t candidates = 0;
    for (std::filesystem::recursive_directory_iterator iterator(kToolsRoot, error), end; iterator != end;
         iterator.increment(error)) {
        if (error) {
            return std::unexpected(
                Failure{FailureCode::IoFailure, kToolsRoot.generic_string(), "failed while auditing tool roots"});
        }
        if (iterator->is_symlink(error)) {
            iterator.disable_recursion_pending();
            continue;
        }
        if (!iterator->is_regular_file(error) || iterator->path().filename() != "tool.json") {
            continue;
        }
        if (++candidates > 4'096) {
            return std::unexpected(Failure{FailureCode::LimitExceeded, "tools", "tool candidate count exceeds 4096"});
        }
        const auto kRelative = std::filesystem::relative(iterator->path(), snapshot.root, error).generic_string();
        if (error || !listed.contains(portableLowercasePath(kRelative))) {
            return std::unexpected(
                Failure{FailureCode::InvalidManifest, kRelative, "tool manifest is not listed in repository.json"});
        }
    }
    return {};
}

} // namespace

Result<std::vector<EvidenceAuthorityInfo>> readEvidenceAuthorities(const std::filesystem::path& repositoryRoot,
                                                                   const std::filesystem::path& indexPath) {
    return readAuthorities(repositoryRoot, indexPath);
}

Status rejectUnlistedEvidenceAuthorities(const std::filesystem::path& repositoryRoot,
                                         std::string_view indexRelativePath,
                                         const std::vector<EvidenceAuthorityInfo>& authorities) {
    return rejectUnlisted(repositoryRoot, indexRelativePath, authorities);
}

Result<RepositorySnapshot> validateRepository(const std::filesystem::path& repositoryRoot) {
    std::error_code canonicalError;
    const auto kCanonicalRepository = std::filesystem::weakly_canonical(repositoryRoot, canonicalError);
    if (canonicalError) {
        return std::unexpected(
            Failure{FailureCode::InvalidPath, repositoryRoot.generic_string(), "repository root cannot be resolved"});
    }
    if (auto oracle = verifySchemaOracleVersion(kCanonicalRepository); !oracle) {
        return std::unexpected(oracle.error());
    }
    const std::array kShapeAuthorities{
        std::pair{"schemas/repository.schema.json", "repository.json"},
        std::pair{"schemas/dependency-catalog.schema.json", "third_party/catalog.json"},
        std::pair{"schemas/toolchain-lock.schema.json", "third_party/toolchain.lock.json"},
        std::pair{"schemas/artifact-lock.schema.json", "third_party/artifacts.lock.json"},
    };
    for (const auto& [schema, instance] : kShapeAuthorities) {
        if (auto shape =
                validateJsonShape(kCanonicalRepository, kCanonicalRepository / schema, kCanonicalRepository / instance);
            !shape) {
            return std::unexpected(shape.error());
        }
    }

    auto root = resolveRepositoryPath(repositoryRoot, "repository.json");
    if (!root) {
        return std::unexpected(root.error());
    }
    auto input = readBoundedFile(*root);
    if (!input) {
        return std::unexpected(input.error());
    }

    simdjson::dom::parser parser;
    auto rootObject = parseObject(parser, *input, *root);
    if (!rootObject) {
        return std::unexpected(rootObject.error());
    }
    std::int64_t schemaVersion = 0;
    if (const auto kError = (*rootObject).at_key("schemaVersion").get_int64().get(schemaVersion);
        (kError != 0) || schemaVersion != 4) {
        return std::unexpected(Failure{FailureCode::InvalidManifest, "repository.json", "schemaVersion must be 4"});
    }

    auto toolPaths = requiredStringArray(*rootObject, "tools", *root, false);
    if (!toolPaths) {
        return std::unexpected(toolPaths.error());
    }

    RepositorySnapshot snapshot{
        .root = kCanonicalRepository, .tools = {}, .evidenceIndexPath = {}, .evidenceAuthorities = {}};
    std::set<std::string, std::less<>> ids;
    std::set<std::string, std::less<>> targets;
    std::set<std::string, std::less<>> ownedPaths;
    for (auto& relativePath : *toolPaths) {
        auto manifest = resolveRepositoryPath(snapshot.root, relativePath);
        if (!manifest) {
            return std::unexpected(manifest.error());
        }
        auto tool = validateToolManifest(snapshot.root, *manifest, relativePath);
        if (!tool) {
            return std::unexpected(tool.error());
        }

        const auto kIdKey = portableLowercasePath(tool->id);
        const auto kTargetKey = portableLowercasePath(tool->cmakeTarget);
        const auto kPathKey = portableLowercasePath(tool->manifestPath);
        if (!ids.insert(kIdKey).second || !targets.insert(kTargetKey).second || !ownedPaths.insert(kPathKey).second) {
            return std::unexpected(
                Failure{FailureCode::OwnershipCollision, relativePath, "tool ID, target, or path ownership collides"});
        }
        snapshot.tools.emplace_back(std::move(*tool));
    }

    std::ranges::sort(snapshot.tools, {}, &ToolInfo::id);
    if (auto status = rejectUnlistedToolManifests(snapshot); !status) {
        return std::unexpected(status.error());
    }

    auto indexRelativePath = requiredString(*rootObject, "evidenceIndex", *root);
    if (!indexRelativePath) {
        return std::unexpected(indexRelativePath.error());
    }
    auto indexPath = resolveRepositoryPath(snapshot.root, *indexRelativePath);
    if (!indexPath) {
        return std::unexpected(indexPath.error());
    }
    auto indexKind = classifyPath(snapshot.root / std::filesystem::path(*indexRelativePath));
    if (!indexKind) {
        return std::unexpected(indexKind.error());
    }
    if (*indexKind != FileKind::Regular) {
        return std::unexpected(Failure{FailureCode::InvalidPath,
                                       *indexRelativePath,
                                       std::string("the evidence index is a ") + fileKindName(*indexKind)});
    }
    // The index references the shared evidence definitions, and a reference
    // resolves against its own absolute identifier rather than against a
    // sibling file, so the import is handed over explicitly.
    const std::array<std::filesystem::path, 1> kEvidenceImports{snapshot.root /
                                                                "schemas/evidence-common-v1.schema.json"};
    if (auto shape = validateJsonShape(
            snapshot.root, snapshot.root / "schemas/evidence-index-v1.schema.json", *indexPath, kEvidenceImports);
        !shape) {
        return std::unexpected(shape.error());
    }
    snapshot.evidenceIndexPath = std::move(*indexRelativePath);
    auto authorities = readEvidenceAuthorities(snapshot.root, *indexPath);
    if (!authorities) {
        return std::unexpected(authorities.error());
    }
    snapshot.evidenceAuthorities = std::move(*authorities);
    if (auto status =
            rejectUnlistedEvidenceAuthorities(snapshot.root, snapshot.evidenceIndexPath, snapshot.evidenceAuthorities);
        !status) {
        return std::unexpected(status.error());
    }

    if (auto status = validateDependencyAuthorities(snapshot.root, snapshot); !status) {
        return std::unexpected(status.error());
    }
    return snapshot;
}

} // namespace rawframe::tool::evidence
