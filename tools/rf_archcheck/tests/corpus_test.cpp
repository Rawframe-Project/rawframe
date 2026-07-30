#include "repository_fixture.h"
#include "rule_corpus.h"

#include <gtest/gtest.h>
#include <string>

namespace rawframe::tool::archcheck {

namespace {

// One rule, written out in full, so that every defect case below differs from a
// loadable corpus by exactly the thing it is testing.
std::string corpusWith(std::string_view rules,
                       std::string_view seal = "fnv1a64:0000000000000000",
                       std::string_view policyVersion = "1") {
    std::string document = "{\n";
    document += "  \"$schema\": \"../../../schemas/archcheck-rules-v1.schema.json\",\n";
    document += "  \"schemaVersion\": 1,\n";
    document += "  \"policyVersion\": " + std::string(policyVersion) + ",\n";
    document += "  \"ruleSetSeal\": \"" + std::string(seal) + "\",\n";
    document += "  \"policyHistory\": [\n    {\n      \"policyVersion\": " + std::string(policyVersion) +
                ",\n      \"ruleSetSeal\": \"" + std::string(seal) + "\"\n    }\n  ],\n";
    document += "  \"rules\": [\n" + std::string(rules) + "\n  ]\n}\n";
    return document;
}

constexpr std::string_view kWellFormedRule = R"(    {
      "id": "RA1002",
      "authority": "spec.0001",
      "title": "A manifest whose stored bytes are not its maintained form.",
      "subjectKind": "manifest",
      "severity": "finding",
      "landsWith": "now"
    })";

} // namespace

TEST(RuleCorpus, LoadsTheRepositoryCorpusAndAgreesWithItsRecordedSeal) {
    auto corpus = loadRuleCorpus(testing::repositoryRoot() / "tools/rf_archcheck/rules/architecture-rules.json");
    ASSERT_TRUE(corpus.has_value()) << corpus.error().message;
    EXPECT_EQ(sealRules(corpus->rules), corpus->ruleSetSeal);
    EXPECT_FALSE(corpus->rules.empty());
}

TEST(RuleCorpus, EveryRuleCitesExactlyOneAcceptedAuthority) {
    auto corpus = loadRuleCorpus(testing::repositoryRoot() / "tools/rf_archcheck/rules/architecture-rules.json");
    ASSERT_TRUE(corpus.has_value());
    for (const auto& rule : corpus->rules) {
        EXPECT_FALSE(rule.authority.empty()) << rule.id;
        EXPECT_EQ(rule.authority.find(','), std::string::npos) << rule.id;
        EXPECT_EQ(rule.severity, "finding") << rule.id;
    }
}

TEST(RuleCorpus, RefusesARuleWithNoAuthority) {
    constexpr std::string_view kRule = R"(    {
      "id": "RA1002",
      "title": "A manifest whose stored bytes are not its maintained form.",
      "subjectKind": "manifest",
      "severity": "finding",
      "landsWith": "now"
    })";
    auto parsed = parseJson(corpusWith(kRule));
    ASSERT_TRUE(parsed.has_value());
    auto corpus = parseRuleCorpus(*parsed);
    ASSERT_FALSE(corpus.has_value());
    EXPECT_EQ(corpus.error().code, FailureCode::InvalidCorpus);
}

TEST(RuleCorpus, RefusesARuleThatCitesTwoAuthorities) {
    // Two authorities cannot be written as two members, because the grammar
    // fixes the member set, so the only way to try is to write both into one
    // value. That is the case this refuses.
    constexpr std::string_view kRule = R"(    {
      "id": "RA1002",
      "authority": "spec.0001,adr.0004",
      "title": "A manifest whose stored bytes are not its maintained form.",
      "subjectKind": "manifest",
      "severity": "finding",
      "landsWith": "now"
    })";
    auto parsed = parseJson(corpusWith(kRule));
    ASSERT_TRUE(parsed.has_value());
    auto corpus = parseRuleCorpus(*parsed);
    ASSERT_FALSE(corpus.has_value());
    EXPECT_NE(corpus.error().message.find("exactly one accepted authority"), std::string::npos);
}

TEST(RuleCorpus, RefusesARuleCarryingAMemberTheGrammarDoesNotDefine) {
    constexpr std::string_view kRule = R"(    {
      "id": "RA1002",
      "authority": "spec.0001",
      "title": "A manifest whose stored bytes are not its maintained form.",
      "subjectKind": "manifest",
      "severity": "finding",
      "landsWith": "now",
      "waiver": "until later"
    })";
    auto parsed = parseJson(corpusWith(kRule));
    ASSERT_TRUE(parsed.has_value());
    auto corpus = parseRuleCorpus(*parsed);
    ASSERT_FALSE(corpus.has_value());
}

TEST(RuleCorpus, RefusesADuplicateIdentity) {
    const std::string kRules = std::string(kWellFormedRule) + ",\n" + std::string(kWellFormedRule);
    auto parsed = parseJson(corpusWith(kRules));
    ASSERT_TRUE(parsed.has_value());
    auto corpus = parseRuleCorpus(*parsed);
    ASSERT_FALSE(corpus.has_value());
    EXPECT_NE(corpus.error().message.find("ordered by identity"), std::string::npos);
}

TEST(RuleCorpus, RefusesASeverityOtherThanFinding) {
    constexpr std::string_view kRule = R"(    {
      "id": "RA1002",
      "authority": "spec.0001",
      "title": "A manifest whose stored bytes are not its maintained form.",
      "subjectKind": "manifest",
      "severity": "advisory",
      "landsWith": "now"
    })";
    auto parsed = parseJson(corpusWith(kRule));
    ASSERT_TRUE(parsed.has_value());
    auto corpus = parseRuleCorpus(*parsed);
    ASSERT_FALSE(corpus.has_value());
    EXPECT_NE(corpus.error().message.find("severity"), std::string::npos);
}

TEST(RuleCorpus, TheSealChangesWhenAnyRuleValueChanges) {
    Rule rule{"RA1002",
              "spec.0001",
              "A manifest whose stored bytes are not its maintained form.",
              "manifest",
              "finding",
              "now"};
    const std::string kBefore = sealRules({rule});
    rule.landsWith = "TASK-0011";
    EXPECT_NE(sealRules({rule}), kBefore);
    rule.landsWith = "now";
    rule.title += " ";
    EXPECT_NE(sealRules({rule}), kBefore);
}

TEST(RuleCorpus, RefusesAHistoryWhoseVersionsDoNotIncrease) {
    std::string document = "{\n  \"policyVersion\": 2,\n  \"ruleSetSeal\": \"fnv1a64:0000000000000000\",\n";
    document += "  \"policyHistory\": [\n    {\n      \"policyVersion\": 2,\n      \"ruleSetSeal\": "
                "\"fnv1a64:0000000000000000\"\n    },\n    {\n      \"policyVersion\": 1,\n      \"ruleSetSeal\": "
                "\"fnv1a64:0000000000000001\"\n    }\n  ],\n";
    document += "  \"rules\": [\n" + std::string(kWellFormedRule) + "\n  ]\n}\n";
    auto parsed = parseJson(document);
    ASSERT_TRUE(parsed.has_value());
    auto corpus = parseRuleCorpus(*parsed);
    ASSERT_FALSE(corpus.has_value());
    EXPECT_NE(corpus.error().message.find("do not increase"), std::string::npos);
}

} // namespace rawframe::tool::archcheck
