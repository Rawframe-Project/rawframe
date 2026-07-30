#include "repository_validator.h"
#include "shipping_closure.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

namespace {

const std::filesystem::path& realRoot() {
    static const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    return kRoot;
}

// The audit reads five kinds of evidence: repository membership, each tool
// manifest, each tool's build files, the forbidden shipping roots, and the
// absence of a production module manifest. A scratch root carrying exactly
// those inputs is enough to violate each one in isolation, and copying the real
// files means a failing check names the mutation rather than a fixture that
// never resembled the repository.
std::filesystem::path scratchRootFor(std::string_view name) {
    const auto kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "shipping_closure" / name;
    std::filesystem::remove_all(kRoot);
    std::filesystem::create_directories(kRoot);
    std::filesystem::copy_file(realRoot() / "repository.json", kRoot / "repository.json");
    // Every tool the index lists, not one named tool. The audit iterates
    // membership, so a fixture that copied a fixed tool would stop resembling
    // the repository the moment a second one was admitted.
    auto snapshot = validateRepository(realRoot());
    EXPECT_TRUE(snapshot.has_value()) << snapshot.error().path << ": " << snapshot.error().message;
    for (const auto& tool : snapshot.value_or(RepositorySnapshot{}).tools) {
        const std::filesystem::path kToolRoot =
            std::filesystem::path(tool.manifestPath).parent_path();
        std::filesystem::create_directories(kRoot / kToolRoot / "tests");
        for (const auto* kFile : {"tool.json", "CMakeLists.txt", "tests/CMakeLists.txt"}) {
            std::filesystem::copy_file(realRoot() / kToolRoot / kFile, kRoot / kToolRoot / kFile);
        }
    }
    return kRoot;
}

// The tool list and its manifest paths come from the real validated repository,
// because membership is `repository.json`'s to declare and this suite is not
// testing the validator. Only the root is redirected, so every check reads the
// scratch copy.
RepositorySnapshot snapshotRootedAt(const std::filesystem::path& root) {
    auto snapshot = validateRepository(realRoot());
    EXPECT_TRUE(snapshot.has_value()) << snapshot.error().path << ": " << snapshot.error().message;
    auto value = snapshot.value_or(RepositorySnapshot{});
    value.root = root;
    return value;
}

std::string readText(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

void writeText(const std::filesystem::path& path, std::string_view text) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
}

void mutateFile(const std::filesystem::path& path, std::string_view from, std::string_view to) {
    auto text = readText(path);
    const auto kAt = text.find(from);
    ASSERT_NE(kAt, std::string::npos) << "fixture text not found in " << path.generic_string() << ": " << from;
    text.replace(kAt, from.size(), to);
    writeText(path, text);
}

// Returns the pass flag of the named check, or nothing when the audit did not
// produce that check at all. Distinguishing the two matters: a check that
// silently stopped being emitted would otherwise read as a pass.
std::optional<bool> checkResult(const ShippingClosureAudit& audit, std::string_view check, std::string_view subject) {
    const auto kFound = std::ranges::find_if(audit.checks, [check, subject](const ShippingClosureCheck& candidate) {
        return candidate.check == check && candidate.subject == subject;
    });
    if (kFound == audit.checks.end()) {
        return std::nullopt;
    }
    return kFound->pass;
}

} // namespace

// The harness is verified first. If the scratch copy did not pass, every
// rejection case below would pass without proving anything.
TEST(ShippingClosure, AcceptsAFaithfulCopyOfTheRealClosureEvidence) {
    const auto kRoot = scratchRootFor("baseline");
    auto audit = auditShippingClosure(kRoot, snapshotRootedAt(kRoot));
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    for (const auto& check : audit->checks) {
        EXPECT_TRUE(check.pass) << check.check << ": " << check.subject;
    }
    EXPECT_TRUE(audit->allPassed());
}

TEST(ShippingClosure, RejectsNonEmptyProductionMembership) {
    const auto kRoot = scratchRootFor("production_membership");
    mutateFile(kRoot / "repository.json", "\"modules\": []", "\"modules\": [\"source/base/module.json\"]");

    auto audit = auditShippingClosure(kRoot, snapshotRootedAt(kRoot));
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_EQ(checkResult(*audit, "production_membership_empty", "repository.json"), std::optional{false});
    EXPECT_FALSE(audit->allPassed());
}

// `repositoryOnly` and the three forbidden exposures are separate claims, so
// each is broken on its own. Testing only one would let the others be dropped
// without any test noticing.
TEST(ShippingClosure, RejectsAToolThatIsNotDeclaredRepositoryOnly) {
    const auto kRoot = scratchRootFor("repository_only");
    mutateFile(kRoot / "tools/rf_evidence/tool.json", "\"repositoryOnly\": true", "\"repositoryOnly\": false");

    auto audit = auditShippingClosure(kRoot, snapshotRootedAt(kRoot));
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_EQ(checkResult(*audit, "tool_distribution_forbidden", "rawframe.tool.evidence"), std::optional{false});
    EXPECT_FALSE(audit->allPassed());
}

TEST(ShippingClosure, RejectsAToolManifestThatPermitsShippingClosureEntry) {
    const auto kRoot = scratchRootFor("shipping_closure_field");
    mutateFile(kRoot / "tools/rf_evidence/tool.json",
               "\"shippingClosure\": \"forbidden\"",
               "\"shippingClosure\": \"allowed\"");

    auto audit = auditShippingClosure(kRoot, snapshotRootedAt(kRoot));
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_EQ(checkResult(*audit, "tool_distribution_forbidden", "rawframe.tool.evidence"), std::optional{false});
    EXPECT_FALSE(audit->allPassed());
}

TEST(ShippingClosure, RejectsAToolManifestThatPermitsSdkExposure) {
    const auto kRoot = scratchRootFor("sdk_exposure_field");
    mutateFile(kRoot / "tools/rf_evidence/tool.json", "\"sdkExposure\": \"forbidden\"", "\"sdkExposure\": \"allowed\"");

    auto audit = auditShippingClosure(kRoot, snapshotRootedAt(kRoot));
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_EQ(checkResult(*audit, "tool_distribution_forbidden", "rawframe.tool.evidence"), std::optional{false});
    EXPECT_FALSE(audit->allPassed());
}

TEST(ShippingClosure, RejectsAToolManifestThatPermitsATargetRoot) {
    const auto kRoot = scratchRootFor("target_root_field");
    mutateFile(kRoot / "tools/rf_evidence/tool.json", "\"targetRoot\": \"forbidden\"", "\"targetRoot\": \"allowed\"");

    auto audit = auditShippingClosure(kRoot, snapshotRootedAt(kRoot));
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_EQ(checkResult(*audit, "tool_distribution_forbidden", "rawframe.tool.evidence"), std::optional{false});
    EXPECT_FALSE(audit->allPassed());
}

// An install rule is how a repository tool would leak into a distributed
// artifact, so it is detected in the build files rather than assumed absent.
TEST(ShippingClosure, RejectsAnInstallSurfaceInTheToolBuild) {
    const auto kRoot = scratchRootFor("install_surface");
    auto text = readText(kRoot / "tools/rf_evidence/CMakeLists.txt");
    text += "\ninstall(TARGETS rawframe_tool_rf_evidence)\n";
    writeText(kRoot / "tools/rf_evidence/CMakeLists.txt", text);

    auto audit = auditShippingClosure(kRoot, snapshotRootedAt(kRoot));
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_EQ(checkResult(*audit, "no_install_or_export_surface", "rawframe.tool.evidence"), std::optional{false});
    EXPECT_FALSE(audit->allPassed());
}

TEST(ShippingClosure, RejectsAnExportSurfaceInTheToolTestBuild) {
    const auto kRoot = scratchRootFor("export_surface");
    auto text = readText(kRoot / "tools/rf_evidence/tests/CMakeLists.txt");
    text += "\n    export(TARGETS rawframe_tool_rf_evidence_tests FILE tests.cmake)\n";
    writeText(kRoot / "tools/rf_evidence/tests/CMakeLists.txt", text);

    auto audit = auditShippingClosure(kRoot, snapshotRootedAt(kRoot));
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_EQ(checkResult(*audit, "no_install_or_export_surface", "rawframe.tool.evidence"), std::optional{false});
    EXPECT_FALSE(audit->allPassed());
}

TEST(ShippingClosure, RejectsAPresentShippingRoot) {
    const auto kRoot = scratchRootFor("shipping_root");
    std::filesystem::create_directories(kRoot / "source");

    auto audit = auditShippingClosure(kRoot, snapshotRootedAt(kRoot));
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_EQ(checkResult(*audit, "shipping_root_absent", "source"), std::optional{false});
    // The other forbidden roots are unaffected, which is what keeps this case
    // from passing because the whole audit collapsed.
    EXPECT_EQ(checkResult(*audit, "shipping_root_absent", "sdk"), std::optional{true});
    EXPECT_FALSE(audit->allPassed());
}

TEST(ShippingClosure, RejectsAProductionModuleManifest) {
    const auto kRoot = scratchRootFor("module_manifest");
    writeText(kRoot / "tools/rf_evidence/module.json", "{}\n");

    auto audit = auditShippingClosure(kRoot, snapshotRootedAt(kRoot));
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_EQ(checkResult(*audit, "no_production_module_manifest", "module.json"), std::optional{false});
    EXPECT_FALSE(audit->allPassed());
}

// A missing membership array is a malformed authority rather than a failed
// check, so it must surface as a typed failure instead of a quiet false.
TEST(ShippingClosure, RejectsRepositoryMembershipThatOmitsAnArray) {
    const auto kRoot = scratchRootFor("missing_membership_array");
    mutateFile(kRoot / "repository.json", "\"profiles\": []", "\"profilesRenamed\": []");

    auto audit = auditShippingClosure(kRoot, snapshotRootedAt(kRoot));
    ASSERT_FALSE(audit.has_value());
    EXPECT_EQ(audit.error().code, FailureCode::InvalidManifest);
}

} // namespace rawframe::tool::evidence
