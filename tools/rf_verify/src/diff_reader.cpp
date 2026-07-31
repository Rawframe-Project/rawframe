#include "diff_reader.h"

#include "repository_paths.h"
#include "tool_limits.h"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <ios>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>

namespace rawframe::tool::verify {

namespace {

std::unexpected<Failure> reject(FailureCode code, std::string path, std::string message) {
    return std::unexpected(Failure{code, std::move(path), std::move(message)});
}

// `+++ b/path` is the usual form, but a diff produced without prefixes writes
// `+++ path`, and a deletion writes `+++ /dev/null`. All three are handled here
// rather than by requiring one invocation of one version-control system.
std::string_view stripDiffPrefix(std::string_view path) {
    if (path.starts_with("b/")) {
        return path.substr(2);
    }
    if (path.starts_with("a/")) {
        return path.substr(2);
    }
    return path;
}

std::string_view trimTrailing(std::string_view line) {
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
        line.remove_suffix(1);
    }
    return line;
}

// A `+++` header may carry a tab-separated timestamp after the path.
std::string_view untilTab(std::string_view text) {
    if (const auto kTab = text.find('\t'); kTab != std::string_view::npos) {
        return text.substr(0, kTab);
    }
    return text;
}

Result<std::uint32_t> parseUnsigned(std::string_view text) {
    std::uint32_t value = 0;
    const auto kParsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (kParsed.ec != std::errc{} || kParsed.ptr != text.data() + text.size()) {
        return reject(FailureCode::MalformedDiff, {}, "a hunk header carries a line number that is not a number");
    }
    return value;
}

// `@@ -old,count +new,count @@` where either count may be omitted and means one.
Result<std::uint32_t> parseHunkStart(std::string_view line) {
    const auto kPlus = line.find(" +");
    if (!line.starts_with("@@ -") || kPlus == std::string_view::npos) {
        return reject(FailureCode::MalformedDiff, {}, "a hunk header is not in unified form: " + std::string(line));
    }
    auto rest = line.substr(kPlus + 2);
    const auto kEnd = rest.find(' ');
    if (kEnd == std::string_view::npos) {
        return reject(FailureCode::MalformedDiff, {}, "a hunk header has no closing marker: " + std::string(line));
    }
    auto span = rest.substr(0, kEnd);
    if (const auto kComma = span.find(','); kComma != std::string_view::npos) {
        span = span.substr(0, kComma);
    }
    return parseUnsigned(span);
}

} // namespace

Result<ChangedLines> parseUnifiedDiff(std::string_view bytes) {
    if (bytes.size() > kMaximumDiffBytes) {
        return reject(FailureCode::LimitExceeded, {}, "the diff exceeds the byte limit");
    }

    ChangedLines changed;
    std::string currentFile;
    std::uint32_t nextLine = 0;
    bool inHunk = false;

    std::size_t offset = 0;
    while (offset <= bytes.size()) {
        const auto kBreak = bytes.find('\n', offset);
        const auto kLine = trimTrailing(
            bytes.substr(offset, kBreak == std::string_view::npos ? std::string_view::npos : kBreak - offset));
        offset = kBreak == std::string_view::npos ? bytes.size() + 1 : kBreak + 1;

        if (kLine.starts_with("+++ ")) {
            const auto kPath = untilTab(kLine.substr(4));
            currentFile = kPath == "/dev/null" ? std::string{} : normalizeSeparators(stripDiffPrefix(kPath));
            inHunk = false;
            continue;
        }
        if (kLine.starts_with("--- ") || kLine.starts_with("diff ") || kLine.starts_with("index ")) {
            inHunk = false;
            continue;
        }
        if (kLine.starts_with("@@")) {
            auto start = parseHunkStart(kLine);
            if (!start) {
                return std::unexpected(start.error());
            }
            nextLine = *start;
            inHunk = true;
            continue;
        }
        if (!inHunk || currentFile.empty()) {
            continue;
        }

        if (kLine.starts_with("+")) {
            if (changed.files.size() >= kMaximumDiffFiles && !changed.files.contains(currentFile)) {
                return reject(FailureCode::LimitExceeded, {}, "the diff exceeds the changed-file limit");
            }
            auto& lines = changed.files[currentFile];
            if (lines.size() >= kMaximumChangedLinesPerFile) {
                return reject(FailureCode::LimitExceeded, currentFile, "the diff exceeds the changed-line limit");
            }
            lines.insert(nextLine);
            ++nextLine;
            continue;
        }
        if (kLine.starts_with("-") || kLine.starts_with("\\")) {
            // A removed line and a no-newline marker both occupy no position in
            // the new file, so neither advances it.
            continue;
        }
        if (kLine.starts_with(" ") || kLine.empty()) {
            ++nextLine;
            continue;
        }
        // Anything else ends the hunk: a diff may be followed by unrelated text
        // and consuming it as context would invent changed lines.
        inHunk = false;
    }
    return changed;
}

Result<ChangedLines> readUnifiedDiff(const std::filesystem::path& diffPath) {
    // `exists` reports false whenever it sets the error code, so the error is
    // already folded into this test.
    std::error_code error;
    if (!std::filesystem::exists(diffPath, error)) {
        return reject(FailureCode::MissingInput, diffPath.generic_string(), "the diff file does not exist");
    }
    // A regular file, not merely something that exists. On Linux a directory
    // opens as a stream and yields nothing, so the read succeeds and produces an
    // empty change set, which a caller cannot tell from a diff that genuinely
    // touched no line. Asking what the path is answers that on both hosts and
    // before anything has been read.
    if (!std::filesystem::is_regular_file(diffPath, error)) {
        return reject(FailureCode::IoFailure, diffPath.generic_string(), "the diff path is not a readable file");
    }
    std::ifstream input(diffPath, std::ios::binary);
    if (!input) {
        return reject(FailureCode::IoFailure, diffPath.generic_string(), "the diff file cannot be read");
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    if (input.bad()) {
        return reject(FailureCode::IoFailure, diffPath.generic_string(), "the diff file cannot be read");
    }
    auto parsed = parseUnifiedDiff(buffer.str());
    if (!parsed) {
        Failure failure = parsed.error();
        if (failure.path.empty()) {
            failure.path = diffPath.generic_string();
        }
        return std::unexpected(failure);
    }
    return parsed;
}

} // namespace rawframe::tool::verify
