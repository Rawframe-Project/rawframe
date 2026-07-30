#pragma once

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace rawframe::tool::archcheck::testing {

[[nodiscard]] inline std::filesystem::path outputRoot() {
    return std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "archcheck";
}

[[nodiscard]] inline std::filesystem::path repositoryRoot() {
    return std::filesystem::path(RAWFRAME_TEST_REPOSITORY_ROOT);
}

// A repository small enough to reason about and complete enough to check. Every
// negative case is this tree with exactly one thing changed, so a test that
// fires proves the change caused it rather than the fixture being wrong in some
// other way.
class RepositoryFixture {
public:
    using Membership = std::pair<std::string, std::vector<std::string>>;

    explicit RepositoryFixture(std::string_view name) : root_(outputRoot() / name) {
        std::error_code code;
        std::filesystem::remove_all(root_, code);
        std::filesystem::create_directories(root_, code);
        writeIndex({});
        write("evidence/evidence.json", "{\"recordKind\":\"evidence_index\",\"schemaVersion\":1}\n");
        write("CMakeLists.txt", "cmake_minimum_required(VERSION 4.4.0)\nproject(fixture LANGUAGES CXX)\n");
        write("third_party/catalog.json",
              "{\n  \"$schema\": \"../schemas/dependency-catalog.schema.json\",\n"
              "  \"schemaVersion\": 1,\n  \"entries\": []\n}\n");
        writeCorpusFromRepository();
    }

    RepositoryFixture(const RepositoryFixture&) = delete;
    RepositoryFixture& operator=(const RepositoryFixture&) = delete;
    RepositoryFixture(RepositoryFixture&&) = delete;
    RepositoryFixture& operator=(RepositoryFixture&&) = delete;
    ~RepositoryFixture() = default;

    [[nodiscard]] const std::filesystem::path& root() const noexcept {
        return root_;
    }

    [[nodiscard]] static std::string corpusRelativePath() {
        return "rules/architecture-rules.json";
    }

    [[nodiscard]] std::filesystem::path corpusPath() const {
        return root_ / corpusRelativePath();
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

    // The root index, with the tools array carrying whatever the case needs.
    void writeIndex(const std::vector<std::string>& tools) const {
        writeIndexWith({{"tools", tools}});
    }

    // The root index with the named membership arrays carrying the given
    // entries. Every array is always written, because an index missing one is a
    // different defect from an index listing the wrong thing.
    void writeIndexWith(const std::vector<Membership>& overrides) const {
        std::string document = "{\n  \"$schema\": \"schemas/repository.schema.json\",\n  \"schemaVersion\": 4,\n";
        for (const std::string_view kName : {"modules",
                                             "targets",
                                             "platforms",
                                             "configurations",
                                             "instrumentations",
                                             "packagingPolicies",
                                             "profiles",
                                             "tools"}) {
            std::vector<std::string> entries;
            for (const auto& chosen : overrides) {
                if (chosen.first == kName) {
                    entries = chosen.second;
                }
            }
            document += "  \"" + std::string(kName) + "\": [";
            if (entries.empty()) {
                document += "],\n";
                continue;
            }
            document += "\n";
            for (std::size_t index = 0; index < entries.size(); ++index) {
                document += "    \"" + entries.at(index) + "\"";
                document += index + 1 < entries.size() ? ",\n" : "\n";
            }
            document += "  ],\n";
        }
        document += "  \"evidenceIndex\": \"evidence/evidence.json\"\n}\n";
        write("repository.json", document);
    }

    // The last rule, removed entire. The last one, because removing any other
    // would also break the identity ordering the grammar requires, and a corpus
    // that fails to load would prove something other than a disabled rule.
    std::string removeLastRuleFromCorpus() const {
        static constexpr std::string_view kSeparator = ",\n    {\n      \"id\": \"";
        std::string contents = readCorpus();
        const auto kLast = contents.rfind(kSeparator);
        if (kLast == std::string::npos) {
            return {};
        }
        const std::size_t kIdStart = kLast + kSeparator.size();
        const auto kIdEnd = contents.find('"', kIdStart);
        if (kIdEnd == std::string::npos) {
            return {};
        }
        std::string identity = contents.substr(kIdStart, kIdEnd - kIdStart);
        const auto kEnd = contents.find("\n  ]", kLast);
        if (kEnd == std::string::npos) {
            return {};
        }
        contents.erase(kLast, kEnd - kLast);
        write(corpusRelativePath(), contents);
        return identity;
    }

    // One literal replacement in the copied corpus. Used to change a rule value
    // without touching the seal, which is the only way to observe a corpus whose
    // seal no longer follows its rules.
    void mutateCorpus(std::string_view from, std::string_view to) const {
        std::string contents = readCorpus();
        const auto kAt = contents.find(from);
        if (kAt == std::string::npos) {
            return;
        }
        contents.replace(kAt, from.size(), to);
        write(corpusRelativePath(), contents);
    }

    // The real corpus, copied byte for byte. A fixture with its own rule set
    // would prove that the fixture's rules work, which is not the question.
    void writeCorpusFromRepository() const {
        const std::filesystem::path kSource = repositoryRoot() / "tools/rf_archcheck/rules/architecture-rules.json";
        std::ifstream stream(kSource, std::ios::binary);
        const std::string kContents((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        write(corpusRelativePath(), kContents);
    }

private:
    [[nodiscard]] std::string readCorpus() const {
        std::ifstream stream(corpusPath(), std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    }

    std::filesystem::path root_;
};

} // namespace rawframe::tool::archcheck::testing
