#pragma once

#include <filesystem>
#include <fstream>
#include <ios>
#include <string>
#include <string_view>
#include <system_error>

namespace rawframe::tool::verify::testing {

[[nodiscard]] inline std::filesystem::path outputRoot() {
    return std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "verify";
}

[[nodiscard]] inline std::filesystem::path repositoryRoot() {
    return std::filesystem::path(RAWFRAME_TEST_REPOSITORY_ROOT);
}

// A repository small enough to reason about and complete enough to measure.
// Every negative case is this tree with exactly one thing changed, so a test
// that fires proves the change caused it rather than the fixture being wrong in
// some other way.
class RepositoryFixture {
public:
    explicit RepositoryFixture(std::string_view name) : root_(outputRoot() / name) {
        std::error_code code;
        std::filesystem::remove_all(root_, code);
        std::filesystem::create_directories(root_, code);
        writeIndex(R"(["tools/subject/tool.json"])");
        write("tools/subject/tool.json", "{\n  \"id\": \"rawframe.tool.subject\"\n}\n");
        write("tools/subject/src/parser.cpp", "int parse(int value) { return value; }\n");
        writeTiers(R"([{"path": "src/parser.cpp", "tier": "A", "reason": "the subject unit"}])");
    }

    RepositoryFixture(const RepositoryFixture&) = delete;
    RepositoryFixture& operator=(const RepositoryFixture&) = delete;
    RepositoryFixture(RepositoryFixture&&) = delete;
    RepositoryFixture& operator=(RepositoryFixture&&) = delete;
    ~RepositoryFixture() = default;

    [[nodiscard]] const std::filesystem::path& root() const noexcept {
        return root_;
    }

    void write(std::string_view relativePath, std::string_view contents) const {
        const std::filesystem::path kPath = root_ / relativePath;
        std::error_code code;
        std::filesystem::create_directories(kPath.parent_path(), code);
        std::ofstream stream(kPath, std::ios::binary | std::ios::trunc);
        stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    }

    void remove(std::string_view relativePath) const {
        std::error_code code;
        std::filesystem::remove_all(root_ / relativePath, code);
    }

    void writeIndex(std::string_view toolsArray) const {
        std::string document = "{\n  \"$schema\": \"schemas/repository.schema.json\",\n  \"schemaVersion\": 4,\n";
        document += "  \"modules\": [],\n";
        document += "  \"tools\": " + std::string(toolsArray) + "\n}\n";
        write("repository.json", document);
    }

    void writeTiers(std::string_view unitsArray) const {
        std::string document = "{\n  \"schemaVersion\": 1,\n  \"units\": " + std::string(unitsArray) + "\n}\n";
        write("tools/subject/tests/verification-tiers.json", document);
    }

    // A coverage export naming the subject unit, with whatever branch and MC/DC
    // material the case needs. The absolute filename is the fixture's own path,
    // because that is what llvm-cov writes and what the reader has to relate
    // back to a repository-relative unit.
    [[nodiscard]] std::string
    exportFor(std::string_view branches, std::string_view mcdcRecords = "[]", std::string_view segments = "[]") const {
        std::string filename = (root_ / "tools/subject/src/parser.cpp").generic_string();
        std::string escaped;
        for (const char kCharacter : filename) {
            if (kCharacter == '\\') {
                escaped += "\\\\";
                continue;
            }
            escaped += kCharacter;
        }
        std::string document = R"({"version":"3.1.0","type":"llvm.coverage.json.export","data":[{"files":[{)";
        document += "\"filename\":\"" + escaped + "\",";
        document += "\"branches\":" + std::string(branches) + ",";
        document += "\"mcdc_records\":" + std::string(mcdcRecords) + ",";
        document += "\"segments\":" + std::string(segments) + ",";
        document += R"("summary":{"lines":{"count":1,"covered":1},"branches":{"count":2,"covered":1},)";
        document += R"("regions":{"count":1,"covered":1},"mcdc":{"count":0,"covered":0}}}]}]})";
        return document;
    }

    std::filesystem::path writeExport(std::string_view branches,
                                      std::string_view mcdcRecords = "[]",
                                      std::string_view segments = "[]") const {
        write("out/coverage/export.json", exportFor(branches, mcdcRecords, segments));
        return root_ / "out/coverage/export.json";
    }

    std::filesystem::path writeDiff(std::string_view contents) const {
        write("out/coverage/changed.diff", contents);
        return root_ / "out/coverage/changed.diff";
    }

private:
    std::filesystem::path root_;
};

// One hunk adding the given line range to the subject unit.
[[nodiscard]] inline std::string diffAddingSubjectLines(int firstLine, int count) {
    std::string document = "diff --git a/tools/subject/src/parser.cpp b/tools/subject/src/parser.cpp\n";
    document += "--- a/tools/subject/src/parser.cpp\n";
    document += "+++ b/tools/subject/src/parser.cpp\n";
    document += "@@ -1,0 +" + std::to_string(firstLine) + "," + std::to_string(count) + " @@\n";
    for (int index = 0; index < count; ++index) {
        document += "+a line\n";
    }
    return document;
}

} // namespace rawframe::tool::verify::testing
