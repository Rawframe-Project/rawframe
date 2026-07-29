#include "schema_oracle.h"

#include "json_policy.h"
#include "process_runner.h"

#include <algorithm>
#include <cctype>
#include <ranges>
#include <string>

namespace rawframe::tool::evidence {

namespace {

std::filesystem::path oraclePath(const std::filesystem::path& repositoryRoot) {
#ifdef _WIN32
    return repositoryRoot / "out/prepared/windows-x86_64/tools/jsonschema/bin/jsonschema.exe";
#else
    return repositoryRoot / "out/prepared/linux-x86_64/tools/jsonschema/bin/jsonschema";
#endif
}

std::string trimAsciiWhitespace(std::string value) {
    const auto kIsNotSpace = [](unsigned char character) {
        return std::isspace(character) == 0;
    };
    const auto kBegin = std::ranges::find_if(value, kIsNotSpace);
    const auto kReverseEnd = std::ranges::find_if(value | std::views::reverse, kIsNotSpace).base();
    if (kBegin >= kReverseEnd) {
        return {};
    }
    return std::string(kBegin, kReverseEnd);
}

ProcessRequest requestFor(const std::filesystem::path& repositoryRoot, std::vector<std::string> arguments) {
    return ProcessRequest{
        .executable = oraclePath(repositoryRoot),
        .arguments = std::move(arguments),
        .workingDirectory = repositoryRoot,
        .captureDirectory = repositoryRoot / "out/reports/task-0001/oracle_capture",
    };
}

} // namespace

Status verifySchemaOracleVersion(const std::filesystem::path& repositoryRoot) {
    auto result = runBoundedProcess(requestFor(repositoryRoot, {"version"}));
    if (!result) {
        return std::unexpected(result.error());
    }
    if (result->exitCode != 0 || trimAsciiWhitespace(result->standardOutput) != "16.1.0" ||
        !trimAsciiWhitespace(result->standardError).empty()) {
        return std::unexpected(Failure{
            FailureCode::VerificationFailed,
            oraclePath(repositoryRoot).generic_string(),
            "schema oracle identity is not exactly 16.1.0",
        });
    }
    return {};
}

Status validateJsonShape(const std::filesystem::path& repositoryRoot,
                         const std::filesystem::path& schemaPath,
                         const std::filesystem::path& instancePath,
                         std::span<const std::filesystem::path> imports) {
    if (auto schemaAdmission = validateJsonAdmission(schemaPath); !schemaAdmission) {
        return schemaAdmission;
    }
    if (auto instanceAdmission = validateJsonAdmission(instancePath); !instanceAdmission) {
        return instanceAdmission;
    }
    std::vector<std::string> arguments{
        "validate", schemaPath.generic_string(), instancePath.generic_string(), "--json"};
    for (const auto& kImport : imports) {
        // Each import is admitted on its own before it can influence a verdict.
        if (auto importAdmission = validateJsonAdmission(kImport); !importAdmission) {
            return importAdmission;
        }
        arguments.emplace_back("--resolve");
        arguments.push_back(kImport.generic_string());
    }
    auto result = runBoundedProcess(requestFor(repositoryRoot, std::move(arguments)));
    if (!result) {
        return std::unexpected(result.error());
    }
    if (result->exitCode == 0) {
        return {};
    }
    if (result->exitCode == 2) {
        return std::unexpected(Failure{
            FailureCode::InvalidManifest,
            instancePath.generic_string(),
            "generic Draft 2020-12 shape validation failed",
        });
    }
    return std::unexpected(Failure{
        FailureCode::VerificationFailed,
        oraclePath(repositoryRoot).generic_string(),
        "schema oracle terminated with an unexpected exit code",
    });
}

} // namespace rawframe::tool::evidence
