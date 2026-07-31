#include "repository_paths.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace rawframe::tool::verify {

namespace {

std::unexpected<Failure> reject(FailureCode code, std::string path, std::string message) {
    return std::unexpected(Failure{code, std::move(path), std::move(message)});
}

// Windows compares paths without regard to case and Linux does not. The
// comparison used to decide whether one path is inside another therefore folds
// case on Windows only, because folding it on Linux would report two genuinely
// different directories as the same one.
bool sameLexicalPrefix(std::string_view candidate, std::string_view prefix) {
#ifdef _WIN32
    if (candidate.size() < prefix.size()) {
        return false;
    }
    return std::ranges::equal(candidate.substr(0, prefix.size()), prefix, [](char left, char right) {
        return std::tolower(static_cast<unsigned char>(left)) == std::tolower(static_cast<unsigned char>(right));
    });
#else
    return candidate.starts_with(prefix);
#endif
}

// Both prefix comparisons need a directory that ends in a separator, so that
// `tools/rf_verifyx/` cannot pass for a path inside `tools/rf_verify`. One
// helper rather than two copies, so the boundary has one implementation and one
// set of tests.
std::string withTrailingSeparator(std::string text) {
    if (!text.empty() && text.back() != '/') {
        text.push_back('/');
    }
    return text;
}

std::filesystem::path absoluteAgainst(const std::filesystem::path& base, const std::filesystem::path& given) {
    return given.is_absolute() ? given : base / given;
}

// Every path this tool takes from outside is resolved the same way, so the three
// callers share one implementation. Resolution is real filesystem work and a
// hostile path can defeat it: a Windows device name such as `nul` used as a
// directory, or a symlink loop on Linux, both make `weakly_canonical` report an
// error rather than a path. That is the one rejection, and it lives here so
// there is one of it to test rather than three.
Result<std::filesystem::path>
canonicalize(const std::filesystem::path& given, std::string reportedAs, std::string_view subject) {
    std::error_code error;
    auto resolved = std::filesystem::weakly_canonical(given, error);
    if (error) {
        return reject(FailureCode::InvalidPath, std::move(reportedAs), std::string(subject) + " cannot be resolved");
    }
    return resolved;
}

} // namespace

std::string normalizeSeparators(std::string_view path) {
    std::string normalized(path);
    std::ranges::replace(normalized, '\\', '/');
    return normalized;
}

Result<std::filesystem::path> resolveRepositoryRoot(const std::filesystem::path& given) {
    auto canonical = canonicalize(given, given.generic_string(), "the repository root");
    if (!canonical) {
        return std::unexpected(canonical.error());
    }
    // `exists` reports false whenever it sets the error code, so the error is
    // already folded into this test. Asking about it a second time would add an
    // operand that can never decide the outcome on its own.
    std::error_code error;
    if (!std::filesystem::exists(*canonical / "repository.json", error)) {
        return reject(FailureCode::MissingInput,
                      canonical->generic_string(),
                      "the given root has no repository.json and is not this repository");
    }
    return *canonical;
}

Result<std::string> repositoryRelative(const std::filesystem::path& repositoryRoot, std::string_view reportedPath) {
    auto absolute = canonicalize(absoluteAgainst(repositoryRoot, std::filesystem::path(reportedPath)),
                                 std::string(reportedPath),
                                 "the reported path");
    if (!absolute) {
        return std::unexpected(absolute.error());
    }

    const auto kRoot = withTrailingSeparator(normalizeSeparators(repositoryRoot.generic_string()));
    const auto kCandidate = normalizeSeparators(absolute->generic_string());
    if (!sameLexicalPrefix(kCandidate, kRoot)) {
        return reject(
            FailureCode::InvalidPath, std::string(reportedPath), "the reported path is outside the repository");
    }
    return kCandidate.substr(kRoot.size());
}

bool isMaintainedSourceUnit(std::string_view relativePath) {
    if (!relativePath.ends_with(".cpp") && !relativePath.ends_with(".h")) {
        return false;
    }
    if (!relativePath.starts_with("source/") && !relativePath.starts_with("tools/")) {
        return false;
    }
    if (relativePath.contains("/tests/")) {
        return false;
    }
    return relativePath.contains("/src/") || relativePath.contains("/include/");
}

Status ensureWithinReportRoot(const std::filesystem::path& repositoryRoot, const std::filesystem::path& destination) {
    auto absolute = canonicalize(
        absoluteAgainst(repositoryRoot, destination), destination.generic_string(), "the report destination");
    if (!absolute) {
        return std::unexpected(absolute.error());
    }

    const auto kAllowed = withTrailingSeparator(
        normalizeSeparators((repositoryRoot / std::filesystem::path(kReportRoot)).generic_string()));
    if (!sameLexicalPrefix(normalizeSeparators(absolute->generic_string()), kAllowed)) {
        return reject(FailureCode::InvalidPath,
                      destination.generic_string(),
                      std::string("a report may only be written beneath ") + std::string(kReportRoot));
    }
    return {};
}

} // namespace rawframe::tool::verify
