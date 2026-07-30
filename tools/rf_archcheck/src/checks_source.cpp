#include "checks.h"
#include "text_scan.h"

#include <algorithm>
#include <array>
#include <string>
#include <string_view>

namespace rawframe::tool::archcheck {

namespace {

// ADR-0008 admits exactly two extensions for first-party native source. A third
// one is a file the build cannot claim to have compiled deliberately.
constexpr std::array kAdmittedSourceExtensions{
    std::string_view{".cpp"},
    std::string_view{".h"},
};

constexpr std::array kAcquisitionCommands{
    std::string_view{"FetchContent_Declare"},
    std::string_view{"FetchContent_MakeAvailable"},
    std::string_view{"FetchContent_Populate"},
    std::string_view{"ExternalProject_Add"},
};

constexpr std::array kBuildArtifactNames{
    std::string_view{"CMakeCache.txt"},
    std::string_view{"cmake_install.cmake"},
    std::string_view{"compile_commands.json"},
};

constexpr std::array kBuildArtifactExtensions{
    std::string_view{".vcxproj"},
    std::string_view{".sln"},
    std::string_view{".xcodeproj"},
    std::string_view{".o"},
    std::string_view{".obj"},
    std::string_view{".pdb"},
    std::string_view{".ilk"},
    std::string_view{".exp"},
    std::string_view{".suo"},
};

constexpr std::array kDevelopmentEnvironmentRoots{
    std::string_view{".vs/"},
    std::string_view{".idea/"},
    std::string_view{".vscode/"},
};

std::string_view lastSegment(std::string_view path) {
    const auto kSlash = path.find_last_of('/');
    return kSlash == std::string_view::npos ? path : path.substr(kSlash + 1);
}

// The two directories STD-0002 fixes for compiled first-party source: private
// state under `src/` and public headers under `include/`. A manifest or a build
// file beside them is not compiled source and is not a subject here. Test trees
// are deliberately outside: they hold fixtures by design, and a rule about
// compiled source has nothing to say about a fixture.
bool isMaintainedSourceDirectory(std::string_view path) {
    if (!path.starts_with("source/") && !path.starts_with("tools/")) {
        return false;
    }
    if (path.contains("/tests/")) {
        return false;
    }
    return path.contains("/src/") || path.contains("/include/");
}

// The token an include would use for a catalog entry. `library.simdjson` is
// included as `<simdjson.h>` and `library.openssl` as `<openssl/evp.h>`, so the
// identity after the dot is the token to look for.
std::string catalogToken(std::string_view id) {
    const auto kDot = id.find('.');
    return std::string(kDot == std::string_view::npos ? id : id.substr(kDot + 1));
}

} // namespace

void checkSourceHygiene(const RepositoryModel& model, FindingSink& sink) {
    // RA5001 and RA5003: what a build file is allowed to do.
    for (const auto& buildFile : model.buildLane) {
        auto text = readTextFile(model.root / buildFile);
        if (!text) {
            continue;
        }
        // `file` is one command with many modes, so the mode decides which rule
        // applies. The mode is the first argument, on the same line as the call
        // in every form CMake accepts for these two.
        for (const auto& match : findCommandInvocations(*text, "file")) {
            const std::string_view kLine = lineAt(*text, match.position.line);
            if (kLine.contains("GLOB")) {
                sink.reportAt("RA5001", buildFile, match.position, "the build file globs its sources");
            }
            if (kLine.contains("DOWNLOAD") || kLine.contains("UPLOAD")) {
                sink.reportAt(
                    "RA5003", buildFile, match.position, "the build file transfers content at configure time");
            }
        }
        for (const std::string_view kCommand : kAcquisitionCommands) {
            for (const auto& match : findCommandInvocations(*text, kCommand)) {
                sink.reportAt("RA5003",
                              buildFile,
                              match.position,
                              "the build file acquires content with " + std::string(kCommand));
            }
        }
    }

    // RA5002: a compiled file the dialect does not admit.
    for (const auto& file : model.scan.files) {
        if (!isMaintainedSourceDirectory(file.path)) {
            continue;
        }
        const std::string_view kExtension = fileExtension(file.path);
        const bool kAdmitted = std::ranges::any_of(kAdmittedSourceExtensions, [kExtension](std::string_view admitted) {
            return admitted == kExtension;
        });
        if (!kAdmitted) {
            sink.report("RA5002",
                        file.path,
                        "the maintained source directory holds an extension the dialect does not admit: " +
                            std::string(kExtension.empty() ? std::string_view{"(none)"} : kExtension));
        }
    }

    // RA5004: a third-party header a manifest never admitted. Only catalogued
    // libraries are matched: a library outside the catalogue is ADR-0005
    // membership, which `rf-evidence` owns, and judging it here would be the
    // second authority this tool exists to avoid.
    for (const auto& tool : model.tools) {
        for (const auto& file : model.scan.files) {
            if (!file.path.starts_with(tool.root + "/") || !isMaintainedSourceDirectory(file.path)) {
                continue;
            }
            auto text = readTextFile(model.root / file.path);
            if (!text) {
                continue;
            }
            for (const auto& include : findIncludes(*text)) {
                if (!include.angled) {
                    continue;
                }
                for (const auto& entry : model.catalog) {
                    const std::string kToken = catalogToken(entry.id);
                    const bool kMatches = include.target == kToken + ".h" || include.target.starts_with(kToken + "/");
                    if (!kMatches) {
                        continue;
                    }
                    if (std::ranges::find(tool.thirdParty, entry.id) != tool.thirdParty.end()) {
                        continue;
                    }
                    sink.reportAt("RA5004",
                                  file.path,
                                  include.position,
                                  "the source includes " + include.target + " and the manifest does not declare " +
                                      entry.id);
                }
            }
        }
    }

    // RA5005: output and development-environment state in the maintained tree.
    for (const auto& file : model.scan.files) {
        const std::string_view kName = lastSegment(file.path);
        const std::string_view kExtension = fileExtension(file.path);
        const bool kIsArtifact =
            std::ranges::any_of(kBuildArtifactNames,
                                [kName](std::string_view name) {
                                    return name == kName;
                                }) ||
            std::ranges::any_of(kBuildArtifactExtensions, [kExtension](std::string_view extension) {
                return extension == kExtension;
            });
        if (kIsArtifact) {
            sink.report("RA5005", file.path, "a build artifact is committed in the maintained tree");
            continue;
        }
        const bool kIsEnvironment = std::ranges::any_of(kDevelopmentEnvironmentRoots, [&file](std::string_view root) {
            return file.path.starts_with(root);
        });
        if (kIsEnvironment) {
            sink.report("RA5005", file.path, "a development-environment project is committed in the maintained tree");
        }
    }
    for (const auto& directory : model.scan.directories) {
        if (lastSegment(directory) != "CMakeFiles") {
            continue;
        }
        sink.report("RA5005", directory, "an in-source build directory exists in the maintained tree");
    }
}

} // namespace rawframe::tool::archcheck
