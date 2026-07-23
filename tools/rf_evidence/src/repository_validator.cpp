#include "repository_validator.h"

#include "dependency_authority.h"
#include "file_reader.h"
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
    if (!schema || !id) {
        return std::unexpected(!schema ? schema.error() : id.error());
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
        .cmakeTarget = std::move(*target),
        .thirdPartyDependencies = std::move(*thirdParty),
        .managedToolDependencies = std::move(*managedTools),
    };
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
        (kError != 0) || schemaVersion != 3) {
        return std::unexpected(Failure{FailureCode::InvalidManifest, "repository.json", "schemaVersion must be 3"});
    }

    auto toolPaths = requiredStringArray(*rootObject, "tools", *root, false);
    if (!toolPaths) {
        return std::unexpected(toolPaths.error());
    }

    RepositorySnapshot snapshot{.root = kCanonicalRepository, .tools = {}};
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
    if (auto status = validateDependencyAuthorities(snapshot.root, snapshot); !status) {
        return std::unexpected(status.error());
    }
    return snapshot;
}

} // namespace rawframe::tool::evidence
