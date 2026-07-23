#include "json_policy.h"

#include "file_reader.h"

#include <cstddef>
#include <set>
#include <simdjson.h>
#include <string>

namespace rawframe::tool::evidence {

namespace {

Status validateElement(simdjson::dom::element element,
                       const std::filesystem::path& path,
                       std::size_t depth,
                       std::size_t& nodes) {
    if (depth > 64U) {
        return std::unexpected(
            Failure{FailureCode::LimitExceeded, path.generic_string(), "JSON nesting depth exceeds 64"});
    }
    if (++nodes > 1'000'000U) {
        return std::unexpected(
            Failure{FailureCode::LimitExceeded, path.generic_string(), "JSON node count exceeds 1000000"});
    }

    simdjson::dom::object object;
    if (element.get_object().get(object) == 0) {
        std::set<std::string, std::less<>> members;
        for (const auto kField : object) {
            const std::string kName(kField.key);
            if (!members.insert(kName).second) {
                return std::unexpected(Failure{
                    FailureCode::InvalidJson,
                    path.generic_string(),
                    "JSON object contains duplicate decoded member: " + kName,
                });
            }
            if (auto status = validateElement(kField.value, path, depth + 1U, nodes); !status) {
                return status;
            }
        }
        return {};
    }

    simdjson::dom::array array;
    if (element.get_array().get(array) == 0) {
        for (const auto kChild : array) {
            if (auto status = validateElement(kChild, path, depth + 1U, nodes); !status) {
                return status;
            }
        }
    }
    return {};
}

} // namespace

Status validateJsonAdmission(const std::filesystem::path& path) {
    auto input = readBoundedFile(path);
    if (!input) {
        return std::unexpected(input.error());
    }
    simdjson::dom::parser parser;
    simdjson::dom::element root;
    if (const auto kError = parser.parse(*input).get(root); kError) {
        return std::unexpected(
            Failure{FailureCode::InvalidJson, path.generic_string(), simdjson::error_message(kError)});
    }
    std::size_t nodes = 0;
    return validateElement(root, path, 1U, nodes);
}

} // namespace rawframe::tool::evidence
