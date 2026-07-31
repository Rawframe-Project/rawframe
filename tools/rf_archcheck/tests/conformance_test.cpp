#include "command.h"
#include "engine.h"
#include "repository_fixture.h"
#include "repository_model.h"
#include "rule_corpus.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// The nine conformance items SPEC-0044 requires. Item 1, one positive and one
// negative fixture per rule, is `checks_test.cpp`; items 2 through 9 are here.

namespace rawframe::tool::archcheck {

namespace {

using testing::RepositoryFixture;

CommandOutput run(const std::vector<std::string>& arguments) {
    std::vector<std::string_view> views;
    views.reserve(arguments.size());
    for (const auto& argument : arguments) {
        views.emplace_back(argument);
    }
    return runCommand(std::span<const std::string_view>(views));
}

CommandOutput check(const RepositoryFixture& fixture) {
    return run({"check_repository",
                "--root",
                fixture.root().string(),
                "--corpus",
                testing::RepositoryFixture::corpusRelativePath()});
}

std::vector<Finding> findingsOf(const RepositoryFixture& fixture) {
    auto outcome =
        checkRepository(fixture.root(), fixture.corpusPath(), testing::RepositoryFixture::corpusRelativePath());
    EXPECT_TRUE(outcome.has_value()) << (outcome.has_value() ? std::string{} : outcome.error().message);
    if (!outcome) {
        return {};
    }
    return outcome->findings;
}

// The two orders in which the seeded trees below are built. A scan that leaked
// filesystem order would differ between them and nowhere else.
void seedForOrdering(const RepositoryFixture& fixture, bool reversed) {
    const std::vector<std::pair<std::string, std::string>> kFiles{
        {"tools/aaa/tool.json", "{\n  \"id\": \"rawframe.tool.aaa\"\n}\n"},
        {"tools/bbb/tool.json", "{\n  \"id\": \"rawframe.tool.bbb\"\n}\n"},
        {"CMakeLists.txt",
         "cmake_minimum_required(VERSION 4.4.0)\nfile(GLOB first src/*.cpp)\n"
         "file(GLOB second include/*.h)\n"},
    };
    if (!reversed) {
        for (const auto& file : kFiles) {
            fixture.write(file.first, file.second);
        }
        return;
    }
    for (auto file = kFiles.rbegin(); file != kFiles.rend(); ++file) {
        fixture.write(file->first, file->second);
    }
}

} // namespace

// Item 2. The six violations ADR-0077 names, each producing exactly its typed
// finding and no other. Exactly: a seeded tree that produces the right finding
// alongside three incidental ones has not shown that the rule is precise.
TEST(Conformance, TheSixNamedViolationsEachProduceExactlyTheirTypedFinding) {
    struct Case {
        std::string_view name;
        std::string_view expected;
        void (*seed)(const RepositoryFixture&);
    };
    const std::array kCases{
        Case{"an undeclared edge",
             "RA3001",
             [](const RepositoryFixture& fixture) {
                 fixture.writeIndexWith({{"modules", {"source/base/module.json", "source/result/module.json"}}});
                 fixture.write("source/base/module.json", "{\n  \"id\": \"rawframe.base\"\n}\n");
                 fixture.write("source/result/module.json", "{\n  \"id\": \"rawframe.result\"\n}\n");
                 fixture.write("source/base/src/identity.cpp", "#include <rawframe/result/error.h>\n");
             }},
        Case{"an unlisted module",
             "RA2002",
             [](const RepositoryFixture& fixture) {
                 fixture.write("source/base/module.json", "{\n  \"id\": \"rawframe.base\"\n}\n");
             }},
        Case{"a closure leak",
             "RA4001",
             [](const RepositoryFixture& fixture) {
                 fixture.writeIndexWith({{"targets", {"targets/server/target.json"}}});
                 fixture.write("targets/server/target.json",
                               "{\n  \"id\": \"target.dedicated_server\",\n  \"role\": \"dedicated_server\",\n"
                               "  \"resolvedClosure\": [\n    \"rawframe.render\"\n  ]\n}\n");
             }},
        Case{"a globbed source",
             "RA5001",
             [](const RepositoryFixture& fixture) {
                 fixture.write("CMakeLists.txt",
                               "cmake_minimum_required(VERSION 4.4.0)\nfile(GLOB sources src/*.cpp)\n");
             }},
        Case{"an undeclared vendor include",
             "RA5004",
             [](const RepositoryFixture& fixture) {
                 fixture.write("third_party/catalog.json",
                               "{\n  \"schemaVersion\": 1,\n  \"entries\": [\n    {\n"
                               "      \"id\": \"library.simdjson\",\n"
                               "      \"acquisitionClass\": \"registry_source\"\n    }\n  ]\n}\n");
                 fixture.writeIndexWith({{"tools", {"tools/one/tool.json"}}});
                 fixture.write("tools/one/tool.json",
                               "{\n  \"id\": \"rawframe.tool.one\",\n  \"dependencies\": {\n"
                               "    \"thirdParty\": []\n  }\n}\n");
                 fixture.write("tools/one/src/thing.cpp", "#include <simdjson.h>\n");
             }},
        Case{"a drifted registrar table",
             "RA7001",
             [](const RepositoryFixture& fixture) {
                 fixture.writeIndexWith({{"targets", {"targets/server/target.json"}}});
                 fixture.write("targets/server/target.json",
                               "{\n  \"id\": \"target.dedicated_server\",\n  \"registrarTable\": {\n"
                               "    \"path\": \"targets/server/registrars.json\",\n"
                               "    \"entries\": [\n      \"rawframe.base\"\n    ]\n  }\n}\n");
                 fixture.write("targets/server/registrars.json", "{\n  \"entries\": []\n}\n");
             }},
    };

    for (const auto& seeded : kCases) {
        RepositoryFixture fixture(std::string("seeded-") + std::string(seeded.expected));
        seeded.seed(fixture);
        const std::vector<Finding> kFindings = findingsOf(fixture);
        ASSERT_EQ(kFindings.size(), 1U) << seeded.name << " produced " << kFindings.size() << " findings";
        EXPECT_EQ(kFindings.front().ruleId, seeded.expected) << seeded.name;
    }
}

// Item 3, first half.
TEST(Conformance, TwoInvocationsOverOneTreeProduceByteIdenticalOutput) {
    RepositoryFixture fixture("determinism-repeat");
    seedForOrdering(fixture, false);
    const CommandOutput kFirst = check(fixture);
    const CommandOutput kSecond = check(fixture);
    EXPECT_EQ(kFirst.exitClass, ExitClass::Findings);
    EXPECT_EQ(kFirst.standardOutput, kSecond.standardOutput);
}

// Item 3, second half.
TEST(Conformance, TwoTreesDifferingOnlyInCreationOrderProduceIdenticalOutput) {
    RepositoryFixture forward("determinism-forward");
    RepositoryFixture backward("determinism-backward");
    seedForOrdering(forward, false);
    seedForOrdering(backward, true);
    EXPECT_EQ(check(forward).standardOutput, check(backward).standardOutput);
}

// Item 4. The total order, proved on a collision at each level of it.
TEST(Conformance, FindingsAreTotallyOrderedByRuleThenSubjectThenPosition) {
    RepositoryFixture fixture("ordering");
    seedForOrdering(fixture, false);
    const std::vector<Finding> kFindings = findingsOf(fixture);
    ASSERT_EQ(kFindings.size(), 4U);

    // Two rules, two subjects under the first, two positions under one subject.
    EXPECT_EQ(kFindings.at(0).ruleId, "RA2006");
    EXPECT_EQ(kFindings.at(0).subject, "tools/aaa/tool.json");
    EXPECT_EQ(kFindings.at(1).ruleId, "RA2006");
    EXPECT_EQ(kFindings.at(1).subject, "tools/bbb/tool.json");
    EXPECT_EQ(kFindings.at(2).ruleId, "RA5001");
    EXPECT_EQ(kFindings.at(2).subject, "CMakeLists.txt");
    EXPECT_EQ(kFindings.at(3).ruleId, "RA5001");
    EXPECT_EQ(kFindings.at(3).subject, "CMakeLists.txt");
    ASSERT_TRUE(kFindings.at(2).position.present());
    ASSERT_TRUE(kFindings.at(3).position.present());
    EXPECT_LT(kFindings.at(2).position.line, kFindings.at(3).position.line);
}

// Item 5. One case per exit class, including the distinction the specification
// draws: a manifest that is wrong is a finding, and a manifest that cannot be
// read is not an answer at all.
TEST(Conformance, EveryExitClassIsReachableAndTheMalformedCaseIsNotAFinding) {
    RepositoryFixture clean("exit-clean");
    EXPECT_EQ(check(clean).exitClass, ExitClass::Clean);

    RepositoryFixture violating("exit-findings");
    violating.write("tools/stray/tool.json", "{\n  \"id\": \"rawframe.tool.stray\"\n}\n");
    EXPECT_EQ(check(violating).exitClass, ExitClass::Findings);

    EXPECT_EQ(run({"check_repository"}).exitClass, ExitClass::UsageError);

    RepositoryFixture malformed("exit-internal");
    malformed.writeIndexWith({{"tools", {"tools/one/tool.json"}}});
    malformed.write("tools/one/tool.json", "{ \"id\": \"rawframe.tool.one\" ");
    const CommandOutput kOutput = check(malformed);
    EXPECT_EQ(kOutput.exitClass, ExitClass::InternalError);
    EXPECT_TRUE(kOutput.standardOutput.empty());
}

// Item 6, the load-time half. The corpus cases live in `corpus_test.cpp`; this
// is the statement that a corpus the grammar refuses stops the run rather than
// degrading it to a partial answer.
TEST(Conformance, ACorpusTheGrammarRefusesStopsTheRun) {
    RepositoryFixture missingAuthority("corpus-no-authority");
    missingAuthority.mutateCorpus("\"authority\": \"spec.0001\",\n", "");
    EXPECT_EQ(check(missingAuthority).exitClass, ExitClass::InternalError);

    RepositoryFixture twoAuthorities("corpus-two-authorities");
    twoAuthorities.mutateCorpus("\"authority\": \"spec.0001\"", "\"authority\": \"spec.0001,adr.0004\"");
    EXPECT_EQ(check(twoAuthorities).exitClass, ExitClass::InternalError);

    RepositoryFixture duplicate("corpus-duplicate-id");
    duplicate.mutateCorpus("\"id\": \"RA1003\"", "\"id\": \"RA1002\"");
    EXPECT_EQ(check(duplicate).exitClass, ExitClass::InternalError);
}

// Item 6, the policy half. A corpus edited with its seal brought along but its
// policy version left behind is a finding, not a load failure: the corpus is
// well formed and the history no longer accounts for it.
TEST(Conformance, ACorpusEditWithoutAPolicyVersionIncreaseIsAFinding) {
    RepositoryFixture fixture("corpus-policy");
    auto before = loadRuleCorpus(fixture.corpusPath());
    ASSERT_TRUE(before.has_value());

    fixture.mutateCorpus("\"subjectKind\": \"manifest\"", "\"subjectKind\": \"repository\"");
    auto edited = loadRuleCorpus(fixture.corpusPath());
    ASSERT_TRUE(edited.has_value());
    // The seal follows the rules; the history and the version do not follow the
    // seal. That is exactly the edit the rule exists to catch.
    fixture.mutateCorpus(before->ruleSetSeal, sealRules(edited->rules));

    const std::vector<Finding> kFindings = findingsOf(fixture);
    ASSERT_FALSE(kFindings.empty());
    EXPECT_EQ(kFindings.front().ruleId, "RA1006");
    EXPECT_EQ(kFindings.front().authority, "adr.0077");
    EXPECT_NE(kFindings.front().detail.find("policy history"), std::string::npos);
}

// Item 7. The boundary, enumerated, so that a rule added later has to be written
// into this table and confronted against the list rather than merely compiling.
TEST(Conformance, NoRuleJudgesAPropertyThisSpecificationAssignsToEvidence) {
    constexpr std::array kEvidenceOwned{
        std::string_view{"manifest schema validity"},
        std::string_view{"dependency-catalog and license-index agreement"},
        std::string_view{"locked artifact identity"},
        std::string_view{"offline verification"},
        std::string_view{"path envelopes"},
        std::string_view{"shipping-closure membership for repository tools"},
        std::string_view{"source ownership"},
        std::string_view{"physical line counts"},
        std::string_view{"evidence record operations"},
    };
    const std::vector<std::pair<std::string_view, std::string_view>> kJudged{
        {"RA1002", "maintained manifest byte form"},
        {"RA1003", "membership explicitness"},
        {"RA1004", "tool manifest singularity"},
        {"RA1005", "manifest identity ownership"},
        {"RA1006", "rule corpus policy discipline"},
        {"RA2001", "listed root reality"},
        {"RA2002", "module admission by index"},
        {"RA2003", "build subject discovery"},
        {"RA2004", "accepted module inventory"},
        {"RA2005", "module naming"},
        {"RA2006", "tool admission by index"},
        {"RA3001", "declared versus actual edges"},
        {"RA3002", "edge category use"},
        {"RA3003", "module graph acyclicity"},
        {"RA3004", "build-introduced edges"},
        {"RA3005", "duplicated dependency truth"},
        {"RA4001", "server closure negatives"},
        {"RA4002", "closure selection authority"},
        {"RA4004", "artifact placement negatives"},
        {"RA5001", "build source hygiene"},
        {"RA5002", "admitted source dialect"},
        {"RA5003", "configure-time acquisition"},
        {"RA5004", "declared vendor headers"},
        {"RA5005", "committed build output"},
        {"RA6001", "generated material separation"},
        {"RA6002", "vendored origin records"},
        {"RA6003", "maintained authority placement"},
        {"RA6004", "public header vendor exposure"},
        {"RA7001", "registrar table projection"},
        {"RA7002", "component schema projection"},
    };

    auto corpus = loadRuleCorpus(testing::repositoryRoot() / "tools/rf_archcheck/rules/architecture-rules.json");
    ASSERT_TRUE(corpus.has_value());
    EXPECT_EQ(corpus->rules.size(), kJudged.size());
    for (const auto& rule : corpus->rules) {
        const auto kEntry = std::ranges::find_if(kJudged, [&rule](const auto& judged) {
            return judged.first == rule.id;
        });
        ASSERT_NE(kEntry, kJudged.end()) << rule.id << " judges a property this table does not name";
        for (const std::string_view kOwned : kEvidenceOwned) {
            EXPECT_NE(kEntry->second, kOwned) << rule.id << " judges a property rf-evidence owns";
        }
    }

    // The two identities SPEC-0044 named and the accepted amendments withdrew,
    // for exactly this reason. Their reappearance is the defect the list exists
    // to make visible.
    EXPECT_EQ(corpus->find("RA1001"), nullptr);
    EXPECT_EQ(corpus->find("RA4003"), nullptr);
}

// Item 8. Per closure, over the closures the repository actually declares, and
// with the membership that makes rf-evidence's own audit cover this tool.
TEST(Conformance, TheToolIsAbsentFromEveryDeclaredShippingClosure) {
    auto model = loadRepositoryModel(testing::repositoryRoot(), "tools/rf_archcheck/rules/architecture-rules.json");
    ASSERT_TRUE(model.has_value()) << (model.has_value() ? std::string{} : model.error().message);

    const MembershipArray* targets = model->membershipArray("targets");
    ASSERT_NE(targets, nullptr);
    std::size_t inspected = 0;
    for (const auto& manifest : model->manifests) {
        const bool kIsTarget = std::ranges::find(targets->entries, manifest.path) != targets->entries.end();
        if (!kIsTarget || !manifest.present) {
            continue;
        }
        ++inspected;
        const JsonNode* closure = manifest.document.root.find("resolvedClosure");
        if (closure == nullptr || !closure->isArray()) {
            continue;
        }
        for (const auto& element : closure->elements) {
            for (const auto& tool : model->tools) {
                EXPECT_NE(element.text, tool.id) << manifest.path;
                EXPECT_NE(element.text, tool.cmakeTarget) << manifest.path;
            }
        }
    }
    EXPECT_EQ(inspected, targets->entries.size());

    // Repository-tool closure membership is rf-evidence's property, and its
    // audit iterates the tools array. Being listed there is what puts this tool
    // inside that audit rather than outside it.
    const MembershipArray* tools = model->membershipArray("tools");
    ASSERT_NE(tools, nullptr);
    EXPECT_NE(std::ranges::find(tools->entries, "tools/rf_archcheck/tool.json"), tools->entries.end());
}

// Item 9. Narrowing a rule without amending its authority. The corpus is sealed
// over the rules, so removing one is visible whether or not anyone remembers to
// say they removed it.
TEST(Conformance, DisablingARuleWithoutAmendingItsAuthorityIsItselfAFindingsFailure) {
    RepositoryFixture fixture("governance");
    auto before = loadRuleCorpus(fixture.corpusPath());
    ASSERT_TRUE(before.has_value());
    const std::size_t kBefore = before->rules.size();

    const std::string kRemoved = fixture.removeLastRuleFromCorpus();
    ASSERT_FALSE(kRemoved.empty());
    auto after = loadRuleCorpus(fixture.corpusPath());
    ASSERT_TRUE(after.has_value()) << after.error().message;
    EXPECT_EQ(after->rules.size() + 1, kBefore);
    EXPECT_EQ(after->find(kRemoved), nullptr);
    // The seal and the policy version were not touched, which is the whole of
    // the change: a rule stopped being enforced and nothing else said so.
    EXPECT_EQ(after->ruleSetSeal, before->ruleSetSeal);
    EXPECT_EQ(after->policyVersion, before->policyVersion);

    const CommandOutput kOutput = check(fixture);
    EXPECT_EQ(kOutput.exitClass, ExitClass::Findings);
    EXPECT_NE(kOutput.standardOutput.find("RA1006"), std::string::npos);
}

// The RF1538 through RF1540 retirement, performed in
// `cmake/sync/tests/configure_acquisition_audit.cmake` under TASK-0010 with the
// project owner's approval on 2026-07-31. ADR-0077 requires a retired stage-0
// check to be proved by its replacement firing on the input the retired check
// refused, so each form below is written the way that check's own regular
// expression matched it. A retirement without this proof is a check silently
// deleted, and the three retired here were the only mechanical guard the build
// lane had against acquiring content at configure time.
TEST(Conformance, EveryRetiredAcquisitionCheckHasItsReplacementFiringOnWhatItRefused) {
    struct Retirement {
        std::string_view retired;
        std::string_view replacement;
        std::string_view refused;
    };
    // RF1538 matched two distinct commands and both are proved, because a
    // replacement that caught only the first would leave the second unenforced
    // while the retirement still looked complete.
    constexpr std::array kRetirements{
        Retirement{"RF1538", "RA5003", "FetchContent_Declare(dep)"},
        Retirement{"RF1538", "RA5003", "ExternalProject_Add(dep)"},
        Retirement{"RF1539", "RA5003", "file(DOWNLOAD https://example.invalid/archive out.bin)"},
        Retirement{"RF1540", "RA5001", "file(GLOB sources src/*.cpp)"},
    };
    for (std::size_t index = 0; index < kRetirements.size(); ++index) {
        const Retirement& kCase = kRetirements.at(index);
        const RepositoryFixture kFixture("retired" + std::to_string(index));
        kFixture.write("CMakeLists.txt", "cmake_minimum_required(VERSION 4.4.0)\n" + std::string(kCase.refused) + "\n");
        const std::vector<Finding> kFindings = findingsOf(kFixture);
        const auto kMatch = std::ranges::find_if(kFindings, [&kCase](const Finding& finding) {
            return finding.ruleId == kCase.replacement;
        });
        ASSERT_NE(kMatch, kFindings.end()) << kCase.retired << " was retired and " << kCase.replacement
                                           << " does not fire on what it refused: " << kCase.refused;
        EXPECT_EQ(kMatch->subject, "CMakeLists.txt");
        EXPECT_TRUE(kMatch->position.present()) << "the replacement must say where, as the retired check did";
    }
}

} // namespace rawframe::tool::archcheck
