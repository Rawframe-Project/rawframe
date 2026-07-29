#include "path_audit.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

namespace {

// The audit classifies a tree rather than reading any authority out of it, so a
// synthetic root is the honest subject here: each case places exactly one file
// or directory and asserts which bucket it lands in. Running it against the real
// repository instead would only ever prove the repository is currently clean,
// which is what the acceptance fixture already reports.
std::filesystem::path scratchRootFor(std::string_view name) {
    const auto kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "path_audit" / name;
    std::filesystem::remove_all(kRoot);
    std::filesystem::create_directories(kRoot);
    return kRoot;
}

void writeFile(const std::filesystem::path& path, std::string_view text = "x\n") {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
}

bool containsPath(const std::vector<PathAuditEntry>& entries, std::string_view path) {
    return std::ranges::any_of(entries, [path](const PathAuditEntry& entry) {
        return entry.path == path;
    });
}

std::string classificationOf(const std::vector<PathAuditEntry>& entries, std::string_view path) {
    const auto kFound = std::ranges::find_if(entries, [path](const PathAuditEntry& entry) {
        return entry.path == path;
    });
    return kFound == entries.end() ? std::string{} : kFound->classification;
}

} // namespace

// The harness is verified first: a root holding only envelope material must
// report no violation at all, otherwise every rejection case below would pass
// without proving which file caused it.
TEST(PathAudit, AcceptsATreeThatHoldsOnlyEnvelopeMaterial) {
    const auto kRoot = scratchRootFor("baseline");
    writeFile(kRoot / "repository.json");
    writeFile(kRoot / "cmake/rawframe_repository_tests.cmake");
    writeFile(kRoot / "tools/rf_evidence/src/path_audit.cpp");

    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(audit->envelopeViolations.empty());
    EXPECT_TRUE(audit->unclassifiedRootEntries.empty());
    EXPECT_EQ(audit->envelopeFileCount, 3U);
    EXPECT_EQ(audit->envelopeFiles.size(), audit->envelopeFileCount);
}

// This is the rule the whole unit exists for. A delivered file under a directory
// the Task legitimately touches, but at a path the Task Packet never allowed, is
// a blocking violation rather than a quietly accepted addition.
TEST(PathAudit, RejectsADeliveredFileOutsideTheFrozenWriteEnvelope) {
    const auto kRoot = scratchRootFor("outside_envelope");
    writeFile(kRoot / "repository.json");
    writeFile(kRoot / "tools/rf_other/src/main.cpp");

    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(containsPath(audit->envelopeViolations, "tools/rf_other/src/main.cpp"));
    EXPECT_EQ(classificationOf(audit->envelopeViolations, "tools/rf_other/src/main.cpp"), "outside_envelope");
}

// A file directly beside an allowed schema is still outside the envelope. The
// envelope names schemas one by one, and only the accepted pre-existing
// `.schema.json` projections are read-only material.
TEST(PathAudit, RejectsANewFileBesideTheAllowedSchemas) {
    const auto kRoot = scratchRootFor("schema_sibling");
    writeFile(kRoot / "repository.json");
    writeFile(kRoot / "schemas/notes.md");
    writeFile(kRoot / "schemas/evidence.schema.json");

    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(containsPath(audit->envelopeViolations, "schemas/notes.md"));
    // The schema projection beside it is pre-existing read-only material, so the
    // rejection above is attributable to the one file that broke the rule.
    EXPECT_FALSE(containsPath(audit->envelopeViolations, "schemas/evidence.schema.json"));
    EXPECT_EQ(audit->preexistingFileCount, 1U);
}

TEST(PathAudit, ReportsAnUnknownRootDirectoryWithoutDescendingIntoIt) {
    const auto kRoot = scratchRootFor("unknown_root");
    writeFile(kRoot / "repository.json");
    writeFile(kRoot / "scratch/deep/nested.txt");

    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(containsPath(audit->unclassifiedRootEntries, "scratch"));
    EXPECT_EQ(classificationOf(audit->unclassifiedRootEntries, "scratch"), "unclassified");
    // The directory is reported once. Its contents are neither delivered nor
    // read as authority, so walking into them would only produce noise.
    EXPECT_FALSE(containsPath(audit->unclassifiedRootEntries, "scratch/deep/nested.txt"));
    EXPECT_TRUE(audit->envelopeViolations.empty());
}

TEST(PathAudit, ReportsAnUnknownRootFileAsUnclassifiedRatherThanAsAViolation) {
    const auto kRoot = scratchRootFor("unknown_root_file");
    writeFile(kRoot / "repository.json");
    writeFile(kRoot / "notes.txt");

    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(containsPath(audit->unclassifiedRootEntries, "notes.txt"));
    EXPECT_TRUE(audit->envelopeViolations.empty());
}

// The staging roots are a separate accepted classification. Folding them into
// either of the other two buckets would either fail a clean workspace or hide
// material the landing review has to see.
TEST(PathAudit, SeparatesHistoricalStagingRootsFromBothOtherClassifications) {
    const auto kRoot = scratchRootFor("staging_root");
    writeFile(kRoot / "repository.json");
    writeFile(kRoot / ".codex/session.json");

    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(containsPath(audit->stagingRootEntries, ".codex"));
    EXPECT_EQ(classificationOf(audit->stagingRootEntries, ".codex"), "historical_staging_landing_excluded");
    EXPECT_TRUE(audit->envelopeViolations.empty());
    EXPECT_TRUE(audit->unclassifiedRootEntries.empty());
}

// Generated output and version-control state are the two roots that would
// otherwise dominate the walk, and neither is delivered material.
TEST(PathAudit, SkipsGeneratedOutputAndVersionControlState) {
    const auto kRoot = scratchRootFor("skipped_roots");
    writeFile(kRoot / "repository.json");
    writeFile(kRoot / "out/build/anything.obj");
    writeFile(kRoot / ".git/config");

    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(audit->envelopeViolations.empty());
    EXPECT_TRUE(audit->unclassifiedRootEntries.empty());
    EXPECT_TRUE(audit->stagingRootEntries.empty());
    EXPECT_EQ(audit->envelopeFileCount, 1U);
}

// The envelope is written in lowercase and compared against a lowercased path,
// so a file whose real name carries capitals must still be recognized. A
// case-sensitive comparison here would report `CMakeLists.txt` as a violation on
// every host.
TEST(PathAudit, MatchesEnvelopeEntriesWithoutRegardToCase) {
    const auto kRoot = scratchRootFor("case_folding");
    writeFile(kRoot / "repository.json");
    writeFile(kRoot / "CMakeLists.txt");
    writeFile(kRoot / "CMakePresets.json");

    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(audit->envelopeViolations.empty());
    EXPECT_EQ(audit->envelopeFileCount, 3U);
    // The inventory keeps the real spelling, because it is a file list for the
    // landing review rather than a comparison key.
    EXPECT_NE(std::ranges::find(audit->envelopeFiles, "CMakeLists.txt"), audit->envelopeFiles.end());
}

// A symlink is a violation wherever it appears, including inside the envelope,
// because the audit classifies paths and a link is a second path to material it
// never walked. Creating one requires a privilege the host may withhold, so the
// case reports that rather than passing quietly.
TEST(PathAudit, RejectsASymlinkEvenInsideTheEnvelope) {
    const auto kRoot = scratchRootFor("symlink");
    writeFile(kRoot / "repository.json");
    writeFile(kRoot / "tools/rf_evidence/src/real.cpp");

    std::error_code error;
    std::filesystem::create_symlink("real.cpp", kRoot / "tools/rf_evidence/src/link.cpp", error);
    if (error) {
        GTEST_SKIP() << "this host does not permit symlink creation: " << error.message();
    }

    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(containsPath(audit->envelopeViolations, "tools/rf_evidence/src/link.cpp"));
    EXPECT_EQ(classificationOf(audit->envelopeViolations, "tools/rf_evidence/src/link.cpp"), "symlink");
}

} // namespace rawframe::tool::evidence
