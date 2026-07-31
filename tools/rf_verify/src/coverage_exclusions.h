#pragma once

#include "coverage_export.h"
#include "failure.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::verify {

// Why a branch outcome is not counted against a coverage floor.
//
// STD-0007's amendment of 2026-07-31 admits exactly two, and the condition of
// admitting them is that each is decided from the source bytes rather than from
// anyone's belief that a branch is unreachable. A judgement call here is the
// loophole the standard exists to close, so there is no value in this enum for
// "the author says so", and adding one is an amendment rather than a change of
// implementation.
enum class BranchExclusion : std::uint8_t {
    // The outcome is counted.
    None,
    // The condition is a literal `true` or `false`. The `do { ... } while
    // (false)` idiom is how a macro becomes a single statement, which is a
    // correctness requirement rather than a preference, and its loop condition
    // has an outcome no program can reach.
    ConstantCondition,
    // The region lies in a body the compiler synthesized from a defaulted
    // declaration. There is no source to test, and the counters reported there
    // cannot be reconciled with the program's executions.
    SynthesizedBody,
};

[[nodiscard]] std::string_view branchExclusionName(BranchExclusion exclusion) noexcept;

// The source bytes of one unit, split into physical lines, with the lookup the
// classifier needs. Lines are one-based, as llvm-cov reports them.
class SourceUnit {
public:
    static Result<SourceUnit> read(const std::filesystem::path& path);

    /// The text between two one-based positions, empty when the span is not a
    /// single line or reaches past the line.
    [[nodiscard]] std::string_view
    span(std::uint32_t line, std::uint32_t column, std::uint32_t endLine, std::uint32_t endColumn) const noexcept;

    /// One whole physical line, empty when there is no such line.
    [[nodiscard]] std::string_view line(std::uint32_t number) const noexcept;

private:
    std::string bytes_;
    std::vector<std::string_view> lines_;
};

/// Why the region is not counted, or `None`.
[[nodiscard]] BranchExclusion classifyBranchRegion(const SourceUnit& unit, const BranchRegion& region);

} // namespace rawframe::tool::verify
