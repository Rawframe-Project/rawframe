#pragma once

#include "failure.h"
#include "json_reader.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <span>
#include <string>
#include <vector>

namespace rawframe::tool::verify {

// One branch region as `llvm-cov export` states it. A region carries two
// outcomes, so it contributes two branch conditions, and each is covered when
// its own execution count is nonzero. This is the same arithmetic llvm-cov uses
// for its own branch summary, which is what makes the two agree.
struct BranchRegion {
    std::uint32_t line = 0;
    std::uint32_t column = 0;
    std::int64_t trueCount = 0;
    std::int64_t falseCount = 0;

    [[nodiscard]] bool trueCovered() const noexcept {
        return trueCount > 0;
    }
    [[nodiscard]] bool falseCovered() const noexcept {
        return falseCount > 0;
    }
};

// One executed test vector of one MC/DC decision. A condition that did not
// affect the outcome is absent rather than false, which is what makes masking
// MC/DC expressible: an absent condition matches either value.
struct McdcTestVector {
    // `true` and `false` are values; `absent` is the don't-care the export
    // writes as null.
    enum class ConditionValue : std::uint8_t {
        False,
        True,
        Absent
    };

    std::vector<ConditionValue> conditions;
    bool executed = false;
    bool result = false;
};

struct McdcDecision {
    std::uint32_t line = 0;
    std::uint32_t column = 0;
    std::size_t conditionCount = 0;
    std::vector<McdcTestVector> vectors;
};

// The figures llvm-cov computed for one file. They are read rather than
// recomputed: llvm-cov owns the arithmetic that turns segments into a line
// count, and a second implementation of it here would eventually disagree with
// the tool that produced the artifact of record.
struct CoverageCounts {
    std::int64_t count = 0;
    std::int64_t covered = 0;
};

struct CoverageSummary {
    CoverageCounts lines;
    CoverageCounts branches;
    CoverageCounts regions;
    CoverageCounts mcdc;
};

struct CoverageFile {
    std::string path;
    CoverageSummary summary;
    std::vector<BranchRegion> branches;
    std::vector<McdcDecision> decisions;
    // Line execution counts, derived from the segment list, and used for the
    // uncovered set alone. A line is present here when the export gave it a
    // count; a line the compiler did not instrument has no entry and is not held
    // against anything.
    std::map<std::uint32_t, std::int64_t> lineCounts;
};

struct CoverageExport {
    std::string producerVersion;
    // Keyed by repository-relative path. Files outside the repository, and files
    // that are not maintained first-party source units, are dropped here and the
    // count of what was dropped is kept so a report can say so.
    std::map<std::string, CoverageFile> files;
    std::size_t droppedForeignFiles = 0;
};

// Reads `llvm-cov export` output and keeps only the maintained first-party
// source units of this repository.
[[nodiscard]] Result<CoverageExport> readCoverageExport(const std::filesystem::path& repositoryRoot,
                                                        const std::filesystem::path& exportPath);

// The same, over several exports read as one measurement.
//
// A lane needs this because a profile merged across programs cannot hold more
// than one `main`: the symbol is external and identically named in every
// executable, so llvm-profdata keeps one record for it and llvm-cov then reports
// the others as mismatched and drops their translation unit entirely. The remedy
// is one export per entry point, taken against that program's own profile. The
// exports must describe disjoint sets of source units, and a unit named twice is
// refused rather than resolved, because two measurements of one file are two
// numbers and choosing between them here would publish a figure neither run
// produced.
[[nodiscard]] Result<CoverageExport> readCoverageExports(const std::filesystem::path& repositoryRoot,
                                                         std::span<const std::filesystem::path> exportPaths);

// The same conversion over a document already in hand, for tests that construct
// an export without writing a file.
[[nodiscard]] Result<CoverageExport> buildCoverageExport(const std::filesystem::path& repositoryRoot,
                                                         const JsonNode& document);

// Whether every condition of a decision has an independence pair: two executed
// test vectors that differ in that condition alone, ignoring don't-cares, and
// that reach different outcomes. This is the definition MC/DC states, and
// computing it here is what lets a floor speak about one decision instead of
// about a whole file.
[[nodiscard]] bool decisionIsIndependentlyCovered(const McdcDecision& decision);

} // namespace rawframe::tool::verify
