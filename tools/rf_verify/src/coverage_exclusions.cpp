#include "coverage_exclusions.h"

#include "tool_limits.h"

#include <cstddef>
#include <fstream>
#include <system_error>
#include <utility>

namespace rawframe::tool::verify {

namespace {

std::unexpected<Failure> reject(FailureCode code, std::string path, std::string message) {
    return std::unexpected(Failure{code, std::move(path), std::move(message)});
}

std::string_view trim(std::string_view text) noexcept {
    const auto kFirst = text.find_first_not_of(" \t\r\n");
    if (kFirst == std::string_view::npos) {
        return {};
    }
    return text.substr(kFirst, text.find_last_not_of(" \t\r\n") - kFirst + 1);
}

/// A physical line with its macro continuation removed, so a declaration that a
/// backslash split reads as the declaration it is.
std::string_view withoutContinuation(std::string_view text) noexcept {
    const auto kTrimmed = trim(text);
    if (kTrimmed.ends_with('\\')) {
        return trim(kTrimmed.substr(0, kTrimmed.size() - 1));
    }
    return kTrimmed;
}

} // namespace

std::string_view branchExclusionName(BranchExclusion exclusion) noexcept {
    switch (exclusion) {
    case BranchExclusion::None:
        return "none";
    case BranchExclusion::ConstantCondition:
        return "constant_condition";
    case BranchExclusion::SynthesizedBody:
        return "synthesized_body";
    }
    return "none";
}

Result<SourceUnit> SourceUnit::read(const std::filesystem::path& path) {
    std::error_code error;
    if (!std::filesystem::exists(path, error)) {
        return reject(FailureCode::MissingInput, path.generic_string(), "the source unit does not exist");
    }
    const auto kSize = std::filesystem::file_size(path, error);
    if (error) {
        return reject(FailureCode::IoFailure, path.generic_string(), "the source unit size cannot be read");
    }
    if (kSize > kMaximumJsonBytes) {
        return reject(FailureCode::LimitExceeded, path.generic_string(), "the source unit exceeds the byte limit");
    }

    SourceUnit unit;
    unit.bytes_.resize(static_cast<std::size_t>(kSize));
    std::ifstream stream(path, std::ios::binary);
    stream.read(unit.bytes_.data(), static_cast<std::streamsize>(kSize));
    if (!stream && kSize != 0) {
        return reject(FailureCode::IoFailure, path.generic_string(), "the source unit cannot be read");
    }

    const std::string_view kAll{unit.bytes_};
    std::size_t start = 0;
    while (start <= kAll.size()) {
        const auto kEnd = kAll.find('\n', start);
        if (kEnd == std::string_view::npos) {
            unit.lines_.push_back(kAll.substr(start));
            break;
        }
        unit.lines_.push_back(kAll.substr(start, kEnd - start));
        start = kEnd + 1;
    }
    return unit;
}

std::string_view SourceUnit::line(std::uint32_t number) const noexcept {
    if (number == 0 || static_cast<std::size_t>(number) > lines_.size()) {
        return {};
    }
    return lines_.at(static_cast<std::size_t>(number) - 1);
}

std::string_view SourceUnit::span(std::uint32_t lineNumber,
                                  std::uint32_t column,
                                  std::uint32_t endLine,
                                  std::uint32_t endColumn) const noexcept {
    // A span across lines is not something this classifier reads, and a
    // half-read multi-line span would be worse than none: it would compare a
    // fragment against a keyword and could match by accident.
    if (lineNumber != endLine || column == 0 || endColumn < column) {
        return {};
    }
    const std::string_view kLine = line(lineNumber);
    const auto kFrom = static_cast<std::size_t>(column) - 1;
    const auto kWidth = static_cast<std::size_t>(endColumn - column);
    if (kFrom > kLine.size() || kFrom + kWidth > kLine.size()) {
        return {};
    }
    return kLine.substr(kFrom, kWidth);
}

BranchExclusion classifyBranchRegion(const SourceUnit& unit, const BranchRegion& region) {
    // A defaulted declaration is tested first. Its region is a single character
    // inside a body that does not exist in the source, so reading the span would
    // compare a punctuation mark against a keyword and learn nothing; the
    // declaration itself is what identifies it.
    if (withoutContinuation(unit.line(region.line)).ends_with("= default;")) {
        return BranchExclusion::SynthesizedBody;
    }
    const std::string_view kCondition = trim(unit.span(region.line, region.column, region.endLine, region.endColumn));
    if (kCondition == "true" || kCondition == "false") {
        return BranchExclusion::ConstantCondition;
    }
    return BranchExclusion::None;
}

} // namespace rawframe::tool::verify
