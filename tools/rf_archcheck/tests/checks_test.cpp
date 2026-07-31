#include "engine.h"
#include "repository_fixture.h"
#include "rule_corpus.h"

#include <algorithm>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::archcheck {

namespace {

using testing::RepositoryFixture;

std::vector<Finding> run(const RepositoryFixture& fixture) {
    auto outcome =
        checkRepository(fixture.root(), fixture.corpusPath(), testing::RepositoryFixture::corpusRelativePath());
    EXPECT_TRUE(outcome.has_value()) << (outcome.has_value() ? std::string{} : outcome.error().message);
    if (!outcome) {
        return {};
    }
    return outcome->findings;
}

// Every negative case asserts the exact rule and the exact authority. A test
// that only asserted that something failed would pass while the wrong rule
// fired, which is the failure this corpus exists to make impossible.
void expectRule(const RepositoryFixture& fixture, std::string_view ruleId, std::string_view authority) {
    const std::vector<Finding> kFindings = run(fixture);
    const auto kMatch = std::ranges::find_if(kFindings, [ruleId](const Finding& finding) {
        return finding.ruleId == ruleId;
    });
    ASSERT_NE(kMatch, kFindings.end()) << "no " << ruleId << " finding; the run produced " << kFindings.size();
    EXPECT_EQ(kMatch->authority, authority);
    EXPECT_FALSE(kMatch->detail.empty());
    EXPECT_FALSE(kMatch->subject.empty());
}

void expectOnly(const RepositoryFixture& fixture, std::string_view ruleId) {
    const std::vector<Finding> kFindings = run(fixture);
    ASSERT_FALSE(kFindings.empty()) << "expected " << ruleId << " and the run was clean";
    for (const auto& finding : kFindings) {
        EXPECT_EQ(finding.ruleId, ruleId) << "on " << finding.subject << ": " << finding.detail;
    }
}

std::string moduleManifest(std::string_view id, std::string_view dependencies = "") {
    std::string document = "{\n  \"id\": \"" + std::string(id) + "\"";
    if (!dependencies.empty()) {
        document += ",\n  \"dependencies\": {\n" + std::string(dependencies) + "\n  }";
    }
    document += "\n}\n";
    return document;
}

std::string catalogWith(std::string_view entries) {
    return "{\n  \"schemaVersion\": 1,\n  \"entries\": [\n" + std::string(entries) + "\n  ]\n}\n";
}

constexpr std::string_view kSimdjsonEntry = R"(    {
      "id": "library.simdjson",
      "acquisitionClass": "registry_source",
      "provider": {
        "type": "vcpkg",
        "reference": "library.simdjson"
      }
    })";

} // namespace

TEST(Checks, ACleanFixtureProducesNoFindingAtAll) {
    RepositoryFixture fixture("clean");
    EXPECT_TRUE(run(fixture).empty());
}

TEST(Checks, RA1002RefusesAManifestThatIsNotInItsMaintainedForm) {
    RepositoryFixture fixture("ra1002");
    fixture.write("repository.json",
                  "{\"$schema\":\"schemas/repository.schema.json\",\"schemaVersion\":4,"
                  "\"modules\":[],\"targets\":[],\"platforms\":[],\"configurations\":[],"
                  "\"instrumentations\":[],\"packagingPolicies\":[],\"profiles\":[],"
                  "\"tools\":[],\"evidenceIndex\":\"evidence/evidence.json\"}\n");
    expectRule(fixture, "RA1002", "spec.0001");
}

TEST(Checks, RA1003RefusesAMembershipEntryThatIsNotOneExplicitManifest) {
    RepositoryFixture fixture("ra1003");
    fixture.writeIndexWith({{"modules", {"source/*/module.json"}}});
    expectRule(fixture, "RA1003", "spec.0001");
}

TEST(Checks, RA1004RefusesAToolEntryThatIsNotOneToolManifest) {
    RepositoryFixture fixture("ra1004");
    fixture.writeIndexWith({{"tools", {"tools/one/manifest.json"}}});
    expectRule(fixture, "RA1004", "adr.0022");
}

TEST(Checks, RA1005RefusesAManifestCarryingAnIdentityThatBelongsToALock) {
    RepositoryFixture fixture("ra1005");
    fixture.writeIndexWith({{"tools", {"tools/one/tool.json"}}});
    fixture.write("tools/one/tool.json",
                  "{\n  \"id\": \"rawframe.tool.one\",\n"
                  "  \"sourceUrl\": \"https://example.invalid/one.tar\"\n}\n");
    expectRule(fixture, "RA1005", "spec.0002");
}

TEST(Checks, RA1006RefusesRulesThatChangedWithoutTheSealFollowingThem) {
    RepositoryFixture fixture("ra1006");
    // One rule value changed and the recorded seal left alone. Changing the seal
    // instead would test the same disagreement while pinning the literal seal of
    // the day into the test, which the next accepted rule would break.
    fixture.mutateCorpus("\"subjectKind\": \"manifest\"", "\"subjectKind\": \"repository\"");
    expectRule(fixture, "RA1006", "adr.0077");
}

TEST(Checks, RA2001RefusesAListedModuleRootThatIsNotThere) {
    RepositoryFixture fixture("ra2001");
    fixture.writeIndexWith({{"modules", {"source/base/module.json"}}});
    expectRule(fixture, "RA2001", "spec.0007");
}

TEST(Checks, RA2002RefusesAModuleTheIndexDoesNotList) {
    RepositoryFixture fixture("ra2002");
    fixture.write("source/base/module.json", moduleManifest("rawframe.base"));
    expectOnly(fixture, "RA2002");
}

TEST(Checks, RA2003RefusesABuildFileThatDiscoversItsSubjects) {
    RepositoryFixture fixture("ra2003");
    fixture.write("CMakeLists.txt", "cmake_minimum_required(VERSION 4.4.0)\naux_source_directory(src SOURCES)\n");
    expectRule(fixture, "RA2003", "adr.0008");
}

TEST(Checks, RA2004RefusesAModuleIdentityOutsideTheAcceptedInventory) {
    RepositoryFixture fixture("ra2004");
    fixture.writeIndexWith({{"modules", {"source/gizmo/module.json"}}});
    fixture.write("source/gizmo/module.json", moduleManifest("rawframe.gizmo"));
    expectRule(fixture, "RA2004", "adr.0012");
}

TEST(Checks, RA2005RefusesACatchAllModuleName) {
    RepositoryFixture fixture("ra2005");
    fixture.writeIndexWith({{"modules", {"source/utils/module.json"}}});
    fixture.write("source/utils/module.json", moduleManifest("rawframe.utils"));
    expectRule(fixture, "RA2005", "adr.0012");
}

TEST(Checks, RA2006RefusesAToolReachableOnlyByFindingIt) {
    RepositoryFixture fixture("ra2006");
    fixture.write("tools/stray/tool.json", "{\n  \"id\": \"rawframe.tool.stray\"\n}\n");
    expectOnly(fixture, "RA2006");
}

TEST(Checks, RA3001RefusesAnIncludeTheOwningManifestDoesNotDeclare) {
    RepositoryFixture fixture("ra3001");
    fixture.writeIndexWith({{"modules", {"source/base/module.json", "source/result/module.json"}}});
    fixture.write("source/base/module.json", moduleManifest("rawframe.base"));
    fixture.write("source/result/module.json", moduleManifest("rawframe.result"));
    fixture.write("source/base/src/identity.cpp", "#include <rawframe/result/error.h>\n");
    expectOnly(fixture, "RA3001");
}

TEST(Checks, RA3002RefusesAPublicHeaderReachingThroughANonPublicEdge) {
    RepositoryFixture fixture("ra3002");
    fixture.writeIndexWith({{"modules", {"source/base/module.json", "source/result/module.json"}}});
    fixture.write("source/base/module.json",
                  moduleManifest("rawframe.base", "    \"private\": [\n      \"rawframe.result\"\n    ]"));
    fixture.write("source/result/module.json", moduleManifest("rawframe.result"));
    fixture.write("source/base/include/rawframe/base/identity.h", "#include <rawframe/result/error.h>\n");
    expectRule(fixture, "RA3002", "spec.0007");
}

TEST(Checks, RA3003RefusesACycleInTheProductionGraph) {
    RepositoryFixture fixture("ra3003");
    fixture.writeIndexWith({{"modules", {"source/base/module.json", "source/result/module.json"}}});
    fixture.write("source/base/module.json",
                  moduleManifest("rawframe.base", "    \"public\": [\n      \"rawframe.result\"\n    ]"));
    fixture.write("source/result/module.json",
                  moduleManifest("rawframe.result", "    \"public\": [\n      \"rawframe.base\"\n    ]"));
    expectRule(fixture, "RA3003", "adr.0002");
}

TEST(Checks, RA3004RefusesAnEdgeTheBuildFileIntroducesAlone) {
    RepositoryFixture fixture("ra3004");
    fixture.writeIndexWith({{"modules", {"source/base/module.json", "source/result/module.json"}}});
    fixture.write("source/base/module.json", moduleManifest("rawframe.base"));
    fixture.write("source/result/module.json", moduleManifest("rawframe.result"));
    fixture.write("source/base/CMakeLists.txt",
                  "add_library(rawframe_base STATIC)\ntarget_link_libraries(rawframe_base PUBLIC rawframe::result)\n");
    expectRule(fixture, "RA3004", "adr.0004");
}

TEST(Checks, RA3005RefusesDependencyTruthWrittenInTheBuildFileToo) {
    RepositoryFixture fixture("ra3005");
    fixture.write("third_party/catalog.json", catalogWith(kSimdjsonEntry));
    fixture.write("CMakeLists.txt",
                  "cmake_minimum_required(VERSION 4.4.0)\n"
                  "find_package(library.simdjson CONFIG REQUIRED)\n");
    expectRule(fixture, "RA3005", "adr.0004");
}

TEST(Checks, RA4001RefusesAServerClosureThatReachedAClientOnlyModule) {
    RepositoryFixture fixture("ra4001");
    fixture.writeIndexWith({{"targets", {"targets/server/target.json"}}});
    fixture.write("targets/server/target.json",
                  "{\n  \"id\": \"target.dedicated_server\",\n"
                  "  \"role\": \"dedicated_server\",\n"
                  "  \"resolvedClosure\": [\n    \"rawframe.render\"\n  ]\n}\n");
    expectOnly(fixture, "RA4001");
}

TEST(Checks, RA4002RefusesABooleanThatDecidesALinkEdge) {
    RepositoryFixture fixture("ra4002");
    fixture.write("CMakeLists.txt",
                  "cmake_minimum_required(VERSION 4.4.0)\n"
                  "option(WITH_RENDERER \"\" OFF)\n"
                  "if(WITH_RENDERER)\n"
                  "    target_link_libraries(app PRIVATE renderer)\n"
                  "endif()\n");
    expectRule(fixture, "RA4002", "spec.0003");
}

TEST(Checks, RA4004RefusesLoopbackInARemoteArtifact) {
    RepositoryFixture fixture("ra4004");
    fixture.writeIndexWith({{"targets", {"targets/server/target.json"}}});
    fixture.write("targets/server/target.json",
                  "{\n  \"id\": \"target.dedicated_server\",\n"
                  "  \"role\": \"dedicated_server\",\n"
                  "  \"resolvedClosure\": [\n    \"rawframe.network.loopback\"\n  ]\n}\n");
    expectRule(fixture, "RA4004", "spec.0012");
}

TEST(Checks, RA5001RefusesAGlobbedSource) {
    RepositoryFixture fixture("ra5001");
    fixture.write("CMakeLists.txt", "cmake_minimum_required(VERSION 4.4.0)\nfile(GLOB sources src/*.cpp)\n");
    expectOnly(fixture, "RA5001");
}

TEST(Checks, RA5002RefusesAnExtensionTheDialectDoesNotAdmit) {
    RepositoryFixture fixture("ra5002");
    fixture.writeIndexWith({{"tools", {"tools/one/tool.json"}}});
    fixture.write("tools/one/tool.json", "{\n  \"id\": \"rawframe.tool.one\"\n}\n");
    fixture.write("tools/one/src/thing.cc", "int main() { return 0; }\n");
    expectRule(fixture, "RA5002", "adr.0008");
}

TEST(Checks, RA5003RefusesConfigureTimeAcquisition) {
    RepositoryFixture fixture("ra5003");
    fixture.write("CMakeLists.txt", "cmake_minimum_required(VERSION 4.4.0)\nFetchContent_Declare(dep)\n");
    expectRule(fixture, "RA5003", "adr.0005");
}

TEST(Checks, RA5004RefusesAVendorHeaderTheManifestNeverAdmitted) {
    RepositoryFixture fixture("ra5004");
    fixture.write("third_party/catalog.json", catalogWith(kSimdjsonEntry));
    fixture.writeIndexWith({{"tools", {"tools/one/tool.json"}}});
    fixture.write("tools/one/tool.json",
                  "{\n  \"id\": \"rawframe.tool.one\",\n"
                  "  \"dependencies\": {\n    \"thirdParty\": []\n  }\n}\n");
    fixture.write("tools/one/src/thing.cpp", "#include <simdjson.h>\n");
    expectOnly(fixture, "RA5004");
}

TEST(Checks, RA5005RefusesACommittedBuildArtifact) {
    RepositoryFixture fixture("ra5005");
    fixture.write("CMakeCache.txt", "CMAKE_BUILD_TYPE:STRING=Debug\n");
    expectRule(fixture, "RA5005", "adr.0004");
}

TEST(Checks, RA6001RefusesGeneratedMaterialOutsideTheGeneratedRoot) {
    RepositoryFixture fixture("ra6001");
    fixture.write("tools/one/src/table.h", "// @generated by the registrar projection\n");
    expectRule(fixture, "RA6001", "adr.0004");
}

TEST(Checks, RA6002RefusesVendoredMaterialWithoutAnOriginRecord) {
    RepositoryFixture fixture("ra6002");
    fixture.write("third_party/catalog.json", catalogWith(R"(    {
      "id": "library.vendored",
      "acquisitionClass": "vendored_source",
      "provider": {
        "type": "vendor_origin",
        "reference": "third_party/vendored/vendor-origin.json"
      }
    })"));
    expectOnly(fixture, "RA6002");
}

TEST(Checks, RA6003RefusesAMaintainedAuthorityBeneathTheGeneratedRoot) {
    RepositoryFixture fixture("ra6003");
    fixture.writeIndexWith({{"modules", {"out/generated/module.json"}}});
    expectRule(fixture, "RA6003", "adr.0004");
}

TEST(Checks, RA6004RefusesAPublicHeaderThatExposesAVendorHeader) {
    RepositoryFixture fixture("ra6004");
    fixture.write("third_party/catalog.json", catalogWith(kSimdjsonEntry));
    fixture.write("source/base/include/rawframe/base/identity.h", "#include <simdjson.h>\n");
    expectRule(fixture, "RA6004", "adr.0005");
}

TEST(Checks, RA7001RefusesARegistrarTableThatIsNotItsOwnReDerivation) {
    RepositoryFixture fixture("ra7001");
    fixture.writeIndexWith({{"targets", {"targets/server/target.json"}}});
    fixture.write("targets/server/target.json",
                  "{\n  \"id\": \"target.dedicated_server\",\n"
                  "  \"registrarTable\": {\n"
                  "    \"path\": \"targets/server/registrars.json\",\n"
                  "    \"entries\": [\n      \"rawframe.base\"\n    ]\n  }\n}\n");
    fixture.write("targets/server/registrars.json", "{\n  \"entries\": []\n}\n");
    expectOnly(fixture, "RA7001");
}

TEST(Checks, RA7002RefusesAProjectionThatDoesNotCoverItsSchemas) {
    RepositoryFixture fixture("ra7002");
    fixture.writeIndexWith({{"modules", {"source/world/module.json"}}});
    fixture.write("source/world/module.json",
                  "{\n  \"id\": \"rawframe.world\",\n  \"componentSchemas\": [\n"
                  "    \"source/world/schemas/absent.component.luau\"\n  ]\n}\n");
    expectRule(fixture, "RA7002", "adr.0071");
}

TEST(Checks, EveryRuleInTheCorpusHasANegativeCaseInThisFile) {
    // The corpus is the list; this test is the proof that the list was covered.
    // A rule added without a case here fails immediately, which is the only way
    // a rule that does not work stays distinguishable from one with no subjects.
    auto corpus = loadRuleCorpus(testing::repositoryRoot() / "tools/rf_archcheck/rules/architecture-rules.json");
    ASSERT_TRUE(corpus.has_value());
    const std::vector<std::string> kCovered{
        "RA1002", "RA1003", "RA1004", "RA1005", "RA1006", "RA2001", "RA2002", "RA2003", "RA2004", "RA2005",
        "RA2006", "RA3001", "RA3002", "RA3003", "RA3004", "RA3005", "RA4001", "RA4002", "RA4004", "RA5001",
        "RA5002", "RA5003", "RA5004", "RA5005", "RA6001", "RA6002", "RA6003", "RA6004", "RA7001", "RA7002",
    };
    for (const auto& rule : corpus->rules) {
        EXPECT_NE(std::ranges::find(kCovered, rule.id), kCovered.end()) << rule.id << " has no negative case";
    }
    EXPECT_EQ(corpus->rules.size(), kCovered.size());
}

} // namespace rawframe::tool::archcheck
