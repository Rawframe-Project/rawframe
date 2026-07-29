#include "schema_oracle.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

namespace {

const std::filesystem::path& realRoot() {
    static const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    return kRoot;
}

// The oracle is the prepared offline binary named by the toolchain lock, so the
// repository root passed to these cases is the real one. Only the schema and the
// instance are synthetic, which keeps each case about one validation rule
// instead of about whichever committed manifest happened to be handy.
std::filesystem::path scratchDirectoryFor(std::string_view name) {
    const auto kDirectory = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "schema_oracle" / name;
    std::filesystem::remove_all(kDirectory);
    std::filesystem::create_directories(kDirectory);
    return kDirectory;
}

void writeFile(const std::filesystem::path& path, std::string_view text) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
}

constexpr std::string_view kSchema = R"({
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": { "name": { "type": "string" } },
  "required": ["name"],
  "additionalProperties": false
}
)";

} // namespace

// The oracle is pinned by exact version, because a different validator is a
// different verdict. Nothing below means anything if this identity drifts.
TEST(SchemaOracle, VerifiesTheExactPreparedOracleIdentity) {
    auto status = verifySchemaOracleVersion(realRoot());
    EXPECT_TRUE(status.has_value()) << status.error().path << ": " << status.error().message;
}

// A repository root without the prepared oracle must fail rather than silently
// skip validation, which is the shape an unsynced or tampered tree takes.
TEST(SchemaOracle, RejectsARootWithNoPreparedOracle) {
    const auto kDirectory = scratchDirectoryFor("absent_oracle");
    auto status = verifySchemaOracleVersion(kDirectory);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::MissingInput);
}

// The harness is verified first. If a satisfying instance were rejected, every
// rejection case below would pass without proving anything.
TEST(SchemaOracle, AcceptsAnInstanceThatSatisfiesItsSchema) {
    const auto kDirectory = scratchDirectoryFor("satisfying_instance");
    writeFile(kDirectory / "schema.json", kSchema);
    writeFile(kDirectory / "instance.json", "{ \"name\": \"rawframe\" }\n");

    auto status = validateJsonShape(realRoot(), kDirectory / "schema.json", kDirectory / "instance.json");
    EXPECT_TRUE(status.has_value()) << status.error().path << ": " << status.error().message;
}

// A failed shape check is a rejected manifest, not a broken tool. The two are
// separate exit codes and must stay separate failures, because one blocks the
// document and the other blocks the run.
TEST(SchemaOracle, RejectsAnInstanceThatViolatesItsSchema) {
    const auto kDirectory = scratchDirectoryFor("violating_instance");
    writeFile(kDirectory / "schema.json", kSchema);
    writeFile(kDirectory / "instance.json", "{ \"name\": 7 }\n");

    auto status = validateJsonShape(realRoot(), kDirectory / "schema.json", kDirectory / "instance.json");
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidManifest);
    EXPECT_EQ(status.error().path, (kDirectory / "instance.json").generic_string());
    EXPECT_NE(status.error().message.find("shape validation failed"), std::string::npos) << status.error().message;
}

TEST(SchemaOracle, RejectsAnInstanceMissingARequiredMember) {
    const auto kDirectory = scratchDirectoryFor("missing_required");
    writeFile(kDirectory / "schema.json", kSchema);
    writeFile(kDirectory / "instance.json", "{ }\n");

    auto status = validateJsonShape(realRoot(), kDirectory / "schema.json", kDirectory / "instance.json");
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidManifest);
}

// Both inputs pass repository JSON admission before the oracle sees either one.
// The schema is checked as well as the instance, so a malformed schema cannot
// reach the validator and produce an exit code that means something else.
TEST(SchemaOracle, RejectsASchemaThatIsNotAdmissibleJson) {
    const auto kDirectory = scratchDirectoryFor("unreadable_schema");
    writeFile(kDirectory / "schema.json", "{ this is not json");
    writeFile(kDirectory / "instance.json", "{ \"name\": \"rawframe\" }\n");

    auto status = validateJsonShape(realRoot(), kDirectory / "schema.json", kDirectory / "instance.json");
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidJson);
    EXPECT_EQ(status.error().path, (kDirectory / "schema.json").generic_string());
}

TEST(SchemaOracle, RejectsAnInstanceThatIsNotAdmissibleJson) {
    const auto kDirectory = scratchDirectoryFor("unreadable_instance");
    writeFile(kDirectory / "schema.json", kSchema);
    writeFile(kDirectory / "instance.json", "{ \"name\": ");

    auto status = validateJsonShape(realRoot(), kDirectory / "schema.json", kDirectory / "instance.json");
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidJson);
    EXPECT_EQ(status.error().path, (kDirectory / "instance.json").generic_string());
}

// Duplicate members are the case where the admission gate is doing work the
// oracle would not. A JSON validator resolves them by last value and reports a
// pass, so a document whose meaning depends on decoding order must be rejected
// before it is ever validated.
TEST(SchemaOracle, RejectsDuplicateMembersBeforeTheOracleCanResolveThem) {
    const auto kDirectory = scratchDirectoryFor("duplicate_members");
    writeFile(kDirectory / "schema.json", kSchema);
    writeFile(kDirectory / "instance.json", "{ \"name\": 7, \"name\": \"rawframe\" }\n");

    auto status = validateJsonShape(realRoot(), kDirectory / "schema.json", kDirectory / "instance.json");
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidJson);
    EXPECT_NE(status.error().message.find("duplicate decoded member"), std::string::npos) << status.error().message;
}

TEST(SchemaOracle, RejectsAMissingInstance) {
    const auto kDirectory = scratchDirectoryFor("missing_instance");
    writeFile(kDirectory / "schema.json", kSchema);

    auto status = validateJsonShape(realRoot(), kDirectory / "schema.json", kDirectory / "instance.json");
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::MissingInput);
}

} // namespace rawframe::tool::evidence
