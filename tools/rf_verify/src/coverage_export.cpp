#include "coverage_export.h"

#include "repository_paths.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>

namespace rawframe::tool::verify {

namespace {

// The fixed positions `llvm-cov export` uses for a branch region and for the
// decision header of an MC/DC record. Both arrays begin with the same five
// values, which is why the same names serve for each.
constexpr std::size_t kRegionLineStart = 0;
constexpr std::size_t kRegionColumnStart = 1;
constexpr std::size_t kRegionLineEnd = 2;
constexpr std::size_t kRegionColumnEnd = 3;
constexpr std::size_t kBranchTrueCount = 4;
constexpr std::size_t kBranchFileId = 6;
constexpr std::size_t kBranchFalseCount = 5;
constexpr std::size_t kBranchFieldCount = 9;
constexpr std::size_t kMcdcConditionFolding = 9;
constexpr std::size_t kMcdcTestVectors = 10;
constexpr std::size_t kMcdcFieldCount = 11;

constexpr std::size_t kSegmentLine = 0;
constexpr std::size_t kSegmentCount = 2;
constexpr std::size_t kSegmentHasCount = 3;
constexpr std::size_t kSegmentFieldCount = 6;

std::unexpected<Failure> reject(FailureCode code, std::string path, std::string message) {
    return std::unexpected(Failure{code, std::move(path), std::move(message)});
}

Result<std::uint32_t> readLineNumber(const JsonNode& array, std::size_t index) {
    auto value = readIntegerAt(array, index);
    if (!value) {
        return std::unexpected(value.error());
    }
    if (*value < 0 || *value > std::numeric_limits<std::uint32_t>::max()) {
        return reject(FailureCode::InvalidJson, {}, "a line or column is outside the representable range");
    }
    return static_cast<std::uint32_t>(*value);
}

Result<CoverageCounts> readCounts(const JsonNode& summary, std::string_view key) {
    const JsonNode* section = summary.find(key);
    if (section == nullptr || !section->isObject()) {
        return reject(FailureCode::InvalidJson, {}, std::string("the file summary has no ") + std::string(key));
    }
    CoverageCounts counts;
    const JsonNode* count = section->find("count");
    const JsonNode* covered = section->find("covered");
    if (count == nullptr || covered == nullptr) {
        return reject(FailureCode::InvalidJson, {}, std::string("the ") + std::string(key) + " summary is incomplete");
    }
    auto readCount = readInteger(*count);
    if (!readCount) {
        return std::unexpected(readCount.error());
    }
    auto readCovered = readInteger(*covered);
    if (!readCovered) {
        return std::unexpected(readCovered.error());
    }
    counts.count = *readCount;
    counts.covered = *readCovered;
    return counts;
}

Result<CoverageSummary> readSummary(const JsonNode& file) {
    const JsonNode* summary = file.find("summary");
    if (summary == nullptr || !summary->isObject()) {
        return reject(FailureCode::InvalidJson, {}, "a covered file has no summary");
    }
    CoverageSummary result;
    for (const auto& [key, target] : {std::pair<std::string_view, CoverageCounts*>{"lines", &result.lines},
                                      std::pair<std::string_view, CoverageCounts*>{"branches", &result.branches},
                                      std::pair<std::string_view, CoverageCounts*>{"regions", &result.regions}}) {
        auto counts = readCounts(*summary, key);
        if (!counts) {
            return std::unexpected(counts.error());
        }
        *target = *counts;
    }
    // The MC/DC section appears only when the export was produced with MC/DC
    // enabled. Its absence is a lane that did not ask for it, not a malformed
    // export, and the Tier H rule reports the absence where it matters.
    if (auto mcdc = readCounts(*summary, "mcdc"); mcdc) {
        result.mcdc = *mcdc;
    }
    return result;
}

Result<BranchRegion> readBranchRegion(const JsonNode& entry) {
    if (!entry.isArray() || entry.elements.size() < kBranchFieldCount) {
        return reject(FailureCode::InvalidJson, {}, "a branch region is not a nine-field record");
    }
    BranchRegion region;
    for (const auto& [index, target] : {std::pair<std::size_t, std::uint32_t*>{kRegionLineStart, &region.line},
                                        std::pair<std::size_t, std::uint32_t*>{kRegionColumnStart, &region.column},
                                        std::pair<std::size_t, std::uint32_t*>{kRegionLineEnd, &region.endLine},
                                        std::pair<std::size_t, std::uint32_t*>{kRegionColumnEnd, &region.endColumn}}) {
        auto value = readLineNumber(entry, index);
        if (!value) {
            return std::unexpected(value.error());
        }
        *target = *value;
    }
    auto trueCount = readIntegerAt(entry, kBranchTrueCount);
    if (!trueCount) {
        return std::unexpected(trueCount.error());
    }
    auto falseCount = readIntegerAt(entry, kBranchFalseCount);
    if (!falseCount) {
        return std::unexpected(falseCount.error());
    }
    region.trueCount = *trueCount;
    region.falseCount = *falseCount;
    return region;
}

// Adds a region to a list, summing into the one already there at the same exact
// source span. See the note on BranchRegion for why sharing a span makes two
// records one decision.
void mergeRegion(std::vector<BranchRegion>& into, const BranchRegion& region) {
    const auto kExisting = std::ranges::find_if(into, [&region](const BranchRegion& candidate) {
        return candidate.line == region.line && candidate.column == region.column &&
               candidate.endLine == region.endLine && candidate.endColumn == region.endColumn;
    });
    if (kExisting == into.end()) {
        into.push_back(region);
        return;
    }
    // Saturating rather than wrapping. llvm-cov writes the signed maximum where
    // a counter expression could not be evaluated, and adding to that value
    // would turn an unusable number into a negative one, which reads as
    // uncovered and would be a verdict invented by arithmetic.
    const auto kSaturatingAdd = [](std::int64_t left, std::int64_t right) {
        constexpr std::int64_t kCeiling = std::numeric_limits<std::int64_t>::max();
        return (left > kCeiling - right) ? kCeiling : left + right;
    };
    kExisting->trueCount = kSaturatingAdd(kExisting->trueCount, region.trueCount);
    kExisting->falseCount = kSaturatingAdd(kExisting->falseCount, region.falseCount);
}

Status readBranches(const JsonNode& file, CoverageFile& target) {
    const JsonNode* branches = file.find("branches");
    if (branches == nullptr) {
        return {};
    }
    if (!branches->isArray()) {
        return reject(FailureCode::InvalidJson, target.path, "the branch list is not an array");
    }
    for (const auto& entry : branches->elements) {
        auto region = readBranchRegion(entry);
        if (!region) {
            Failure failure = region.error();
            failure.path = target.path;
            return std::unexpected(failure);
        }
        mergeRegion(target.branches, *region);
    }
    return {};
}

// The branch regions an `expansions` block attributes to another file, keyed by
// the absolute filename the block names.
//
// A macro's decisions are instrumented where the macro is defined and executed
// where it is used, and llvm-cov reports the executing counts inside the using
// file's expansion blocks rather than in the defining file's own branch list.
// A reader that skips them measures a header full of macros as though almost
// nothing ran, which is what happened to `rawframe.base`: every assertion in the
// suite executed, and the assertion header still reported one execution.
Status collectExpansionBranches(const JsonNode& file,
                                const std::string& path,
                                std::map<std::string, std::vector<BranchRegion>>& into) {
    const JsonNode* expansions = file.find("expansions");
    if (expansions == nullptr) {
        return {};
    }
    if (!expansions->isArray()) {
        return reject(FailureCode::InvalidJson, path, "the expansion list is not an array");
    }
    for (const auto& expansion : expansions->elements) {
        const JsonNode* names = expansion.find("filenames");
        const JsonNode* branches = expansion.find("branches");
        if (names == nullptr || !names->isArray()) {
            return reject(FailureCode::InvalidJson, path, "an expansion names no files");
        }
        if (branches == nullptr) {
            continue;
        }
        if (!branches->isArray()) {
            return reject(FailureCode::InvalidJson, path, "an expansion branch list is not an array");
        }
        for (const auto& entry : branches->elements) {
            auto region = readBranchRegion(entry);
            if (!region) {
                Failure failure = region.error();
                failure.path = path;
                return std::unexpected(failure);
            }
            auto fileId = readIntegerAt(entry, kBranchFileId);
            if (!fileId) {
                return std::unexpected(fileId.error());
            }
            if (*fileId < 0 || static_cast<std::size_t>(*fileId) >= names->elements.size()) {
                return reject(FailureCode::InvalidJson, path, "an expansion branch names a file the block does not");
            }
            const JsonNode& kName = names->elements.at(static_cast<std::size_t>(*fileId));
            if (!kName.isString()) {
                return reject(FailureCode::InvalidJson, path, "an expansion filename is not a string");
            }
            mergeRegion(into[kName.text], *region);
        }
    }
    return {};
}

Result<McdcTestVector> readTestVector(const JsonNode& entry, std::size_t conditionCount) {
    if (!entry.isObject()) {
        return reject(FailureCode::InvalidJson, {}, "an MC/DC test vector is not an object");
    }
    const JsonNode* conditions = entry.find("conditions");
    const JsonNode* executed = entry.find("executed");
    const JsonNode* result = entry.find("result");
    if (conditions == nullptr || !conditions->isArray() || executed == nullptr || !executed->isBoolean() ||
        result == nullptr || !result->isBoolean()) {
        return reject(FailureCode::InvalidJson, {}, "an MC/DC test vector is incomplete");
    }
    if (conditions->elements.size() != conditionCount) {
        return reject(FailureCode::InvalidJson, {}, "an MC/DC test vector disagrees with its decision width");
    }
    McdcTestVector vector;
    vector.executed = executed->boolean;
    vector.result = result->boolean;
    vector.conditions.reserve(conditionCount);
    for (const auto& condition : conditions->elements) {
        if (condition.isNull()) {
            vector.conditions.push_back(McdcTestVector::ConditionValue::Absent);
            continue;
        }
        if (!condition.isBoolean()) {
            return reject(FailureCode::InvalidJson, {}, "an MC/DC condition is neither a boolean nor null");
        }
        vector.conditions.push_back(condition.boolean ? McdcTestVector::ConditionValue::True
                                                      : McdcTestVector::ConditionValue::False);
    }
    return vector;
}

Status readDecisions(const JsonNode& file, CoverageFile& target) {
    const JsonNode* records = file.find("mcdc_records");
    if (records == nullptr) {
        return {};
    }
    if (!records->isArray()) {
        return reject(FailureCode::InvalidJson, target.path, "the MC/DC record list is not an array");
    }
    for (const auto& entry : records->elements) {
        if (!entry.isArray() || entry.elements.size() < kMcdcFieldCount) {
            return reject(FailureCode::InvalidJson, target.path, "an MC/DC record is not an eleven-field record");
        }
        const JsonNode& kFolding = entry.elements.at(kMcdcConditionFolding);
        const JsonNode& kVectors = entry.elements.at(kMcdcTestVectors);
        if (!kFolding.isArray() || !kVectors.isArray()) {
            return reject(FailureCode::InvalidJson, target.path, "an MC/DC record has no condition or vector list");
        }

        McdcDecision decision;
        auto line = readLineNumber(entry, kRegionLineStart);
        if (!line) {
            return std::unexpected(line.error());
        }
        auto column = readLineNumber(entry, kRegionColumnStart);
        if (!column) {
            return std::unexpected(column.error());
        }
        decision.line = *line;
        decision.column = *column;
        decision.conditionCount = kFolding.elements.size();
        for (const auto& vectorEntry : kVectors.elements) {
            auto vector = readTestVector(vectorEntry, decision.conditionCount);
            if (!vector) {
                Failure failure = vector.error();
                failure.path = target.path;
                return std::unexpected(failure);
            }
            decision.vectors.push_back(std::move(*vector));
        }
        target.decisions.push_back(std::move(decision));
    }
    return {};
}

Status readSegments(const JsonNode& file, CoverageFile& target) {
    const JsonNode* segments = file.find("segments");
    if (segments == nullptr) {
        return {};
    }
    if (!segments->isArray()) {
        return reject(FailureCode::InvalidJson, target.path, "the segment list is not an array");
    }
    for (const auto& entry : segments->elements) {
        if (!entry.isArray() || entry.elements.size() < kSegmentFieldCount) {
            return reject(FailureCode::InvalidJson, target.path, "a segment is not a six-field record");
        }
        const JsonNode& kHasCount = entry.elements.at(kSegmentHasCount);
        if (!kHasCount.isBoolean() || !kHasCount.boolean) {
            continue;
        }
        auto line = readLineNumber(entry, kSegmentLine);
        if (!line) {
            return std::unexpected(line.error());
        }
        auto count = readIntegerAt(entry, kSegmentCount);
        if (!count) {
            return std::unexpected(count.error());
        }
        auto existing = target.lineCounts.find(*line);
        if (existing == target.lineCounts.end()) {
            target.lineCounts.emplace(*line, *count);
            continue;
        }
        existing->second = std::max(existing->second, *count);
    }
    return {};
}

} // namespace

bool decisionIsIndependentlyCovered(const McdcDecision& decision) {
    if (decision.conditionCount == 0) {
        return false;
    }
    for (std::size_t condition = 0; condition < decision.conditionCount; ++condition) {
        bool paired = false;
        for (std::size_t left = 0; left < decision.vectors.size() && !paired; ++left) {
            for (std::size_t right = left + 1; right < decision.vectors.size() && !paired; ++right) {
                const McdcTestVector& kLeft = decision.vectors.at(left);
                const McdcTestVector& kRight = decision.vectors.at(right);
                if (!kLeft.executed || !kRight.executed || kLeft.result == kRight.result) {
                    continue;
                }
                const McdcTestVector::ConditionValue kLeftValue = kLeft.conditions.at(condition);
                const McdcTestVector::ConditionValue kRightValue = kRight.conditions.at(condition);
                if (kLeftValue == McdcTestVector::ConditionValue::Absent ||
                    kRightValue == McdcTestVector::ConditionValue::Absent || kLeftValue == kRightValue) {
                    continue;
                }
                bool othersAgree = true;
                for (std::size_t other = 0; other < decision.conditionCount && othersAgree; ++other) {
                    if (other == condition) {
                        continue;
                    }
                    const McdcTestVector::ConditionValue kOtherLeft = kLeft.conditions.at(other);
                    const McdcTestVector::ConditionValue kOtherRight = kRight.conditions.at(other);
                    // A don't-care condition matches either value, which is what
                    // makes a short-circuited operand pairable at all.
                    othersAgree = kOtherLeft == McdcTestVector::ConditionValue::Absent ||
                                  kOtherRight == McdcTestVector::ConditionValue::Absent || kOtherLeft == kOtherRight;
                }
                paired = othersAgree;
            }
        }
        if (!paired) {
            return false;
        }
    }
    return true;
}

Status
appendCoverageExport(const std::filesystem::path& repositoryRoot, const JsonNode& document, CoverageExport& into) {
    if (!document.isObject()) {
        return reject(FailureCode::InvalidJson, {}, "the coverage export is not an object");
    }
    const JsonNode* type = document.find("type");
    if (type == nullptr || !type->isString() || type->text != "llvm.coverage.json.export") {
        return reject(FailureCode::InvalidJson, {}, "the document is not an llvm-cov export");
    }

    if (const JsonNode* version = document.find("version");
        version != nullptr && version->isString() && into.producerVersion.empty()) {
        into.producerVersion = version->text;
    }

    const JsonNode* data = document.find("data");
    if (data == nullptr || !data->isArray()) {
        return reject(FailureCode::InvalidJson, {}, "the coverage export has no data array");
    }
    // Expansions are collected across the whole document before anything is
    // folded in, because the file a block credits may be read after the block
    // that credits it. Keyed by the absolute name llvm-cov wrote, since that is
    // the only identity the block carries.
    std::map<std::string, std::vector<BranchRegion>> expansionBranches;
    for (const auto& entry : data->elements) {
        const JsonNode* files = entry.find("files");
        if (files == nullptr || !files->isArray()) {
            return reject(FailureCode::InvalidJson, {}, "a coverage export entry has no file list");
        }
        for (const auto& file : files->elements) {
            const JsonNode* name = file.find("filename");
            if (name == nullptr || !name->isString()) {
                return reject(FailureCode::InvalidJson, {}, "a covered file has no filename");
            }
            if (auto status = collectExpansionBranches(file, name->text, expansionBranches); !status) {
                return std::unexpected(status.error());
            }
        }
    }

    for (const auto& entry : data->elements) {
        const JsonNode* files = entry.find("files");
        if (files == nullptr || !files->isArray()) {
            return reject(FailureCode::InvalidJson, {}, "a coverage export entry has no file list");
        }
        for (const auto& file : files->elements) {
            const JsonNode* name = file.find("filename");
            if (name == nullptr || !name->isString()) {
                return reject(FailureCode::InvalidJson, {}, "a covered file has no filename");
            }
            auto relative = repositoryRelative(repositoryRoot, name->text);
            if (!relative || !isMaintainedSourceUnit(*relative)) {
                ++into.droppedForeignFiles;
                continue;
            }
            if (into.files.contains(*relative)) {
                return reject(
                    FailureCode::InvalidJson, *relative, "two coverage exports describe the same source unit");
            }

            CoverageFile target;
            target.path = *relative;
            auto summary = readSummary(file);
            if (!summary) {
                Failure failure = summary.error();
                failure.path = target.path;
                return std::unexpected(failure);
            }
            target.summary = *summary;
            if (auto status = readBranches(file, target); !status) {
                return std::unexpected(status.error());
            }
            if (auto status = readDecisions(file, target); !status) {
                return std::unexpected(status.error());
            }
            if (auto status = readSegments(file, target); !status) {
                return std::unexpected(status.error());
            }
            if (const auto kExpanded = expansionBranches.find(name->text); kExpanded != expansionBranches.end()) {
                for (const auto& region : kExpanded->second) {
                    mergeRegion(target.branches, region);
                }
            }
            into.files.emplace(target.path, std::move(target));
        }
    }
    return {};
}

Result<CoverageExport> buildCoverageExport(const std::filesystem::path& repositoryRoot, const JsonNode& document) {
    CoverageExport result;
    if (auto status = appendCoverageExport(repositoryRoot, document, result); !status) {
        return std::unexpected(status.error());
    }
    return result;
}

Result<CoverageExport> readCoverageExports(const std::filesystem::path& repositoryRoot,
                                           std::span<const std::filesystem::path> exportPaths) {
    CoverageExport result;
    for (const auto& exportPath : exportPaths) {
        auto document = readJsonFile(exportPath);
        if (!document) {
            return std::unexpected(document.error());
        }
        if (auto status = appendCoverageExport(repositoryRoot, *document, result); !status) {
            Failure failure = status.error();
            if (failure.path.empty()) {
                failure.path = exportPath.generic_string();
            }
            return std::unexpected(failure);
        }
    }
    return result;
}

Result<CoverageExport> readCoverageExport(const std::filesystem::path& repositoryRoot,
                                          const std::filesystem::path& exportPath) {
    const std::array kOne{exportPath};
    return readCoverageExports(repositoryRoot, kOne);
}

} // namespace rawframe::tool::verify
