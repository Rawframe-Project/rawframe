#include "offline_verifier.h"

#include "file_reader.h"
#include "json_policy.h"
#include "path_policy.h"
#include "process_runner.h"
#include "sha256.h"

#include <cstdint>
#include <set>
#include <simdjson.h>
#include <string>
#include <vector>

namespace rawframe::tool::evidence {

namespace {

Result<std::string>
stringField(simdjson::dom::object object, std::string_view field, const std::filesystem::path& lockPath) {
    std::string_view value;
    if (const auto kError = object.at_key(field).get_string().get(value); kError) {
        return std::unexpected(Failure{
            FailureCode::InvalidJson,
            lockPath.generic_string(),
            std::string("missing string field ") + std::string(field) + ": " + simdjson::error_message(kError),
        });
    }
    return std::string(value);
}

bool artifactAppliesToHost(std::string_view platform, std::string_view hostId) {
    if (platform == "platform.any") {
        return true;
    }
    if (hostId == "windows-x86_64") {
        return platform == "platform.windows";
    }
    return platform == "platform.linux";
}

struct PreparedExpectation {
    std::filesystem::path path;
    std::uint64_t bytes;
    std::string digest;
    std::string id;
};

Status verifyFileIdentity(const PreparedExpectation& expectation) {
    std::error_code error;
    const auto kBytes = std::filesystem::file_size(expectation.path, error);
    if (error) {
        return std::unexpected(Failure{FailureCode::MissingInput, expectation.id, "prepared file is absent"});
    }
    if (kBytes != expectation.bytes) {
        return std::unexpected(Failure{
            FailureCode::VerificationFailed, expectation.id, "prepared file byte size does not match the lock"});
    }
    auto digest = sha256File(expectation.path);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    if (*digest != expectation.digest) {
        return std::unexpected(
            Failure{FailureCode::VerificationFailed, expectation.id, "prepared file SHA-256 does not match the lock"});
    }
    return {};
}

Status verifyPreparedCommands(const std::filesystem::path& repositoryRoot, std::string_view hostId) {
    const auto kToolsRoot = repositoryRoot / "out" / "prepared" / hostId / "tools";
    for (const std::string_view kTool : {"cmake", "cosign", "gnupg", "seven_zip"}) {
        const auto kMarker = kToolsRoot / kTool / ".rf-prepared.json";
        if (auto admission = validateJsonAdmission(kMarker); !admission) {
            return admission;
        }
    }
#ifdef _WIN32
    const auto kCmake = kToolsRoot / "cmake/bin/cmake.exe";
    const auto kCosign = kToolsRoot / "cosign/bin/cosign.exe";
#else
    const auto cmake = toolsRoot / "cmake/bin/cmake";
    const auto cosign = toolsRoot / "cosign/bin/cosign";
#endif
    auto cmakeResult = runBoundedProcess(ProcessRequest{
        .executable = kCmake,
        .arguments = {"--version"},
        .workingDirectory = repositoryRoot,
        .captureDirectory = repositoryRoot / "out/reports/task-0001/offline_cmake_capture",
    });
    if (!cmakeResult) {
        return std::unexpected(cmakeResult.error());
    }
    if (cmakeResult->exitCode != 0 || !cmakeResult->standardOutput.starts_with("cmake version 4.4.0\n")) {
        return std::unexpected(
            Failure{FailureCode::VerificationFailed, kCmake.generic_string(), "prepared CMake identity mismatch"});
    }
    const auto kBundle = kToolsRoot / "cosign/share/cosign.sigstore.json";
    const auto kTrustedRoot = kToolsRoot / "cosign/share/trusted_root.json";
    auto cosignResult = runBoundedProcess(ProcessRequest{
        .executable = kCosign,
        .arguments =
            {
                "verify-blob",
                "--bundle",
                kBundle.generic_string(),
                "--trusted-root",
                kTrustedRoot.generic_string(),
                "--certificate-identity",
                "keyless@projectsigstore.iam.gserviceaccount.com",
                "--certificate-oidc-issuer",
                "https://accounts.google.com",
                kCosign.generic_string(),
            },
        .workingDirectory = repositoryRoot,
        .captureDirectory = repositoryRoot / "out/reports/task-0001/offline_cosign_capture",
    });
    if (!cosignResult) {
        return std::unexpected(cosignResult.error());
    }
    if (cosignResult->exitCode != 0) {
        return std::unexpected(Failure{FailureCode::VerificationFailed,
                                       kCosign.generic_string(),
                                       "prepared Cosign offline provenance verification failed"});
    }
    return {};
}

} // namespace

Result<OfflineVerificationReport> verifyOfflineInputs(const std::filesystem::path& repositoryRoot,
                                                      std::string_view hostId) {
    if (hostId != "windows-x86_64" && hostId != "linux-x86_64") {
        return std::unexpected(
            Failure{FailureCode::UnsupportedHost, std::string(hostId), "host is outside the TASK-0001 matrix"});
    }

    auto lockPath = resolveRepositoryPath(repositoryRoot, "third_party/artifacts.lock.json");
    if (!lockPath) {
        return std::unexpected(lockPath.error());
    }
    auto input = readBoundedFile(*lockPath);
    if (!input) {
        return std::unexpected(input.error());
    }

    simdjson::dom::parser parser;
    simdjson::dom::element rootElement;
    if (const auto kError = parser.parse(*input).get(rootElement); kError) {
        return std::unexpected(
            Failure{FailureCode::InvalidJson, lockPath->generic_string(), simdjson::error_message(kError)});
    }
    simdjson::dom::object root;
    if (const auto kError = rootElement.get_object().get(root); kError) {
        return std::unexpected(
            Failure{FailureCode::InvalidJson, lockPath->generic_string(), "artifact lock must be an object"});
    }
    simdjson::dom::array artifacts;
    if (const auto kError = root.at_key("artifacts").get_array().get(artifacts); kError) {
        return std::unexpected(
            Failure{FailureCode::InvalidJson, lockPath->generic_string(), "artifact lock has no artifacts array"});
    }

    OfflineVerificationReport report{};
    const auto kPreparedTools = repositoryRoot / "out" / "prepared" / hostId / "tools";
    std::vector<PreparedExpectation> preparedExpectations;
    std::set<std::string, std::less<>> artifactIds;
    for (const auto kElement : artifacts) {
        simdjson::dom::object artifact;
        if (const auto kError = kElement.get_object().get(artifact); kError) {
            return std::unexpected(
                Failure{FailureCode::InvalidJson, lockPath->generic_string(), "artifact entry must be an object"});
        }
        auto id = stringField(artifact, "id", *lockPath);
        if (!id) {
            return std::unexpected(id.error());
        }
        auto platform = stringField(artifact, "platform", *lockPath);
        if (!platform) {
            return std::unexpected(platform.error());
        }
        auto expectedDigest = stringField(artifact, "sha256", *lockPath);
        if (!expectedDigest) {
            return std::unexpected(expectedDigest.error());
        }
        if (!artifactIds.insert(*id).second) {
            return std::unexpected(Failure{FailureCode::OwnershipCollision, *id, "artifact ID is duplicated"});
        }
        if (!artifactAppliesToHost(*platform, hostId)) {
            continue;
        }

        std::uint64_t expectedBytes = 0;
        if (const auto kError = artifact.at_key("byteSize").get_uint64().get(expectedBytes); kError) {
            return std::unexpected(Failure{FailureCode::InvalidJson, *id, "artifact byteSize is missing or invalid"});
        }
        const auto kObjectPath =
            repositoryRoot / "out" / "cache" / "objects" / expectedDigest->substr(0, 2) / *expectedDigest;
        std::error_code fileError;
        const auto kObservedBytes = std::filesystem::file_size(kObjectPath, fileError);
        if (fileError) {
            return std::unexpected(Failure{FailureCode::MissingInput, *id, "verified cache object is absent"});
        }
        if (kObservedBytes != expectedBytes) {
            return std::unexpected(
                Failure{FailureCode::VerificationFailed, *id, "cache object byte size does not match the lock"});
        }
        auto observedDigest = sha256File(kObjectPath);
        if (!observedDigest) {
            return std::unexpected(observedDigest.error());
        }
        if (*observedDigest != *expectedDigest) {
            return std::unexpected(
                Failure{FailureCode::VerificationFailed, *id, "cache object SHA-256 does not match the lock"});
        }

        if (*id == (hostId == "windows-x86_64" ? "tool.cosign.windows_x86_64" : "tool.cosign.linux_x86_64")) {
#ifdef _WIN32
            const auto* const kRelative = "cosign/bin/cosign.exe";
#else
            const auto relative = "cosign/bin/cosign";
#endif
            preparedExpectations.push_back({kPreparedTools / kRelative, expectedBytes, *expectedDigest, *id});
        } else if (*id == (hostId == "windows-x86_64" ? "tool.cosign.windows_x86_64_bundle"
                                                      : "tool.cosign.linux_x86_64_bundle")) {
            preparedExpectations.push_back(
                {kPreparedTools / "cosign/share/cosign.sigstore.json", expectedBytes, *expectedDigest, *id});
        } else if (*id == "authority.sigstore_trusted_root.data") {
            preparedExpectations.push_back(
                {kPreparedTools / "cosign/share/trusted_root.json", expectedBytes, *expectedDigest, *id});
        }

        const bool kIsPreparedArchive = *id == (hostId == "windows-x86_64" ? "tool.archive_extractor.windows_x86_64"
                                                                           : "tool.archive_extractor.linux_x86_64");
        const bool kIsPreparedGpg =
            *id == (hostId == "windows-x86_64" ? "tool.gnupg.windows_x86_64" : "tool.gnupg.linux_x86_64") ||
            (hostId == "linux-x86_64" && *id == "tool.gnupg.linux_x86_64_full");
        if (kIsPreparedArchive || kIsPreparedGpg) {
            simdjson::dom::object archive;
            simdjson::dom::array requiredFiles;
            if ((artifact.at_key("archive").get_object().get(archive) != 0) ||
                (archive.at_key("requiredFiles").get_array().get(requiredFiles) != 0)) {
                return std::unexpected(
                    Failure{FailureCode::InvalidManifest, *id, "prepared tool lacks required-file identities"});
            }
            for (const auto kRequiredElement : requiredFiles) {
                simdjson::dom::object required;
                if (kRequiredElement.get_object().get(required) != 0) {
                    return std::unexpected(
                        Failure{FailureCode::InvalidJson, *id, "required prepared file must be an object"});
                }
                auto relative = stringField(required, "path", *lockPath);
                auto digest = stringField(required, "sha256", *lockPath);
                std::uint64_t bytes = 0;
                if (!relative || !digest || (required.at_key("byteSize").get_uint64().get(bytes) != 0)) {
                    return std::unexpected(
                        Failure{FailureCode::InvalidManifest, *id, "required prepared file identity is incomplete"});
                }
                if (hostId == "linux-x86_64" && relative->starts_with("usr/")) {
                    relative->erase(0, 4);
                }
                const auto* const kToolRoot = kIsPreparedArchive ? "seven_zip" : "gnupg";
                preparedExpectations.push_back(
                    {kPreparedTools / kToolRoot / *relative, bytes, *digest, *id + ":" + *relative});
            }
        }

        ++report.checkedArtifacts;
        report.checkedBytes += kObservedBytes;
    }
    if (report.checkedArtifacts == 0) {
        return std::unexpected(
            Failure{FailureCode::MissingInput, std::string(hostId), "artifact lock selects no inputs for host"});
    }
    for (const auto& expectation : preparedExpectations) {
        if (auto status = verifyFileIdentity(expectation); !status) {
            return std::unexpected(status.error());
        }
    }
    if (auto commands = verifyPreparedCommands(repositoryRoot, hostId); !commands) {
        return std::unexpected(commands.error());
    }
    return report;
}

} // namespace rawframe::tool::evidence
