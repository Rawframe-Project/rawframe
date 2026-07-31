// The side-effect lint SPEC-0046 item 7 and PLAN-0002 both require of this Task.
//
// `RAWFRAME_ASSERT`'s condition is not evaluated in the shipping configuration.
// An effect the program needs, written inside one, therefore happens in two
// configurations and not in the third, and the resulting defect appears only in
// the build nobody debugs. SPEC-0004 forbids it; nothing mechanical enforced it.
//
// Two things about where this lives are worth stating rather than leaving to be
// discovered. It scans `source/` rather than `source/base/`, so it covers every
// production module that exists and every one that lands next, not just the
// module whose tests happen to carry it. And it belongs in the `rf-archcheck`
// corpus, which is the repository's one architecture-conformance authority; it is
// here because TASK-0011's envelope makes `tools/rf_archcheck/src/**` read-only,
// deliberately, so that a rule cannot be narrowed by the change it would judge.
// Moving it is recorded as an obligation of the Task that adds the second
// production module.
//
// What it can decide is syntactic: an increment, a decrement, or an assignment.
// Whether a called function has an effect is not decidable from the text, so the
// lint does not pretend to answer it, and the limit is stated here rather than
// implied by silence.

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <ios>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

/// Indexing spelled as pointer arithmetic. The bounds-safe alternative the
/// analyzer asks for is `at`, which throws, and ADR-0008 disables exceptions;
/// the repository's analysis policy admits pointer arithmetic for exactly this
/// reason. Every call below is bounded by the loop condition above it.
char characterAt(std::string_view text, std::size_t index) {
    return *(text.data() + index);
}

/// Whether an assertion condition carries an effect the surrounding program could
/// need. Increments, decrements, and assignments are the decidable cases.
bool carriesASideEffect(std::string_view condition) {
    for (std::size_t index = 0; index < condition.size(); ++index) {
        const char kCharacter = characterAt(condition, index);
        const char kNext = index + 1 < condition.size() ? characterAt(condition, index + 1) : '\0';
        const char kPrevious = index > 0 ? characterAt(condition, index - 1) : '\0';

        if ((kCharacter == '+' && kNext == '+') || (kCharacter == '-' && kNext == '-')) {
            return true;
        }
        if (kCharacter != '=') {
            continue;
        }
        // An assignment, as distinct from every comparison and compound operator
        // that also spells a `=`.
        if (kNext == '=' || kPrevious == '=' || kPrevious == '!' || kPrevious == '<' || kPrevious == '>' ||
            kPrevious == '+' || kPrevious == '-' || kPrevious == '*' || kPrevious == '/' || kPrevious == '%' ||
            kPrevious == '&' || kPrevious == '|' || kPrevious == '^') {
            continue;
        }
        return true;
    }
    return false;
}

/// Every assertion condition in a source text, with nesting respected so that a
/// comma inside a call does not end the condition early.
///
/// Angle brackets are deliberately not nesting here. A comparison and a template
/// argument list are the same two characters, and an assertion condition is made
/// of comparisons, so counting them would make `index < size` an unterminated
/// nesting. The cost is that a comma inside a template argument list looks like
/// the end of the condition, which the second argument's contract settles: it is
/// always a string literal, so a split whose tail does not begin with one is the
/// wrong split and the scan keeps going.
std::vector<std::string> assertionConditions(std::string_view source) {
    std::vector<std::string> conditions;
    for (const std::string_view kMacro : {"RAWFRAME_ASSERT(", "RAWFRAME_CHECK("}) {
        std::size_t cursor = 0;
        while (true) {
            const std::size_t kFound = source.find(kMacro, cursor);
            if (kFound == std::string_view::npos) {
                break;
            }
            cursor = kFound + kMacro.size();
            // A definition rather than a use: `#define RAWFRAME_ASSERT(condition,
            // message)` names its parameters and asserts nothing.
            const std::size_t kLineStart = source.rfind('\n', kFound);
            const std::string_view kLine =
                source.substr(kLineStart == std::string_view::npos ? 0 : kLineStart + 1, kFound - kLineStart);
            if (kLine.contains("#define")) {
                continue;
            }

            int depth = 1;
            std::size_t scan = cursor;
            while (scan < source.size() && depth > 0) {
                const char kCharacter = characterAt(source, scan);
                if (kCharacter == '(' || kCharacter == '[' || kCharacter == '{') {
                    ++depth;
                } else if (kCharacter == ')' || kCharacter == ']' || kCharacter == '}') {
                    --depth;
                } else if (kCharacter == ',' && depth == 1) {
                    std::size_t tail = scan + 1;
                    while (tail < source.size() &&
                           (characterAt(source, tail) == ' ' || characterAt(source, tail) == '\t')) {
                        ++tail;
                    }
                    if (tail < source.size() && characterAt(source, tail) == '"') {
                        break;
                    }
                }
                ++scan;
            }
            conditions.emplace_back(source.substr(cursor, scan - cursor));
        }
    }
    return conditions;
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    std::ostringstream contents;
    contents << stream.rdbuf();
    return contents.str();
}

/// Every maintained production translation unit and header beneath `source/`.
/// Tests are excluded on purpose: the case that proves a shipping assertion does
/// not evaluate its condition has to write one that would.
std::vector<std::filesystem::path> productionSources() {
    const std::filesystem::path kRoot = std::filesystem::path{RAWFRAME_BASE_SOURCE_ROOT}.parent_path();
    std::vector<std::filesystem::path> paths;
    std::error_code error;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(kRoot, error)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const std::string kGeneric = entry.path().generic_string();
        if (kGeneric.contains("/tests/")) {
            continue;
        }
        const std::string kExtension = entry.path().extension().string();
        if (kExtension == ".h" || kExtension == ".cpp") {
            paths.push_back(entry.path());
        }
    }
    EXPECT_FALSE(error) << "the production source tree beneath " << kRoot.generic_string() << " is unreadable";
    std::ranges::sort(paths);
    return paths;
}

} // namespace

// The lint fires, and does not fire, on a corpus written for the purpose. Base's
// own production code uses no assertion today, so without this the rule would be
// a rule with no subject reporting success.
TEST(AssertionSideEffectLint, DistinguishesAnEffectFromAComparison) {
    RecordProperty("requirement", "SPEC-0046:item-7-assertion-conditions-have-no-side-effects");

    const std::vector<std::string_view> kRejected{
        "++counter > 0",
        "counter++ > 0",
        "--counter >= 0",
        "counter-- >= 0",
        "handle = acquire()",
        "(value = next()) != 0",
    };
    for (const std::string_view kCondition : kRejected) {
        EXPECT_TRUE(carriesASideEffect(kCondition)) << "the lint accepted an effect: " << kCondition;
    }

    const std::vector<std::string_view> kAccepted{
        "counter > 0",
        "left == right",
        "left != right",
        "left <= right",
        "right >= left",
        "!values.empty()",
        "index < size",
        "a + b == c",
        "(mask & flag) != 0",
        "value == kExpected",
    };
    for (const std::string_view kCondition : kAccepted) {
        EXPECT_FALSE(carriesASideEffect(kCondition)) << "the lint rejected a pure condition: " << kCondition;
    }
}

TEST(AssertionSideEffectLint, ExtractsTheConditionAndNotTheMessage) {
    RecordProperty("requirement", "SPEC-0046:item-7-assertion-conditions-have-no-side-effects");

    const auto kConditions =
        assertionConditions("RAWFRAME_CHECK(compare(left, right) == 0, \"a message, with a comma\");\n"
                            "RAWFRAME_ASSERT(index < size, \"in range\");\n");
    ASSERT_EQ(kConditions.size(), 2U);
    EXPECT_EQ(kConditions.front(), "index < size");
    EXPECT_EQ(kConditions.back(), "compare(left, right) == 0");
}

// And the same predicate over the production tree. The scanned count is reported
// so that a run with no subjects is visible as such rather than reading as a
// clean result.
TEST(AssertionSideEffectLint, FindsNoAssertionWithASideEffectInProductionSource) {
    RecordProperty("requirement", "SPEC-0046:item-7-assertion-conditions-have-no-side-effects");

    std::size_t scanned = 0;
    std::vector<std::string> offences;
    for (const std::filesystem::path& path : productionSources()) {
        for (const std::string& condition : assertionConditions(readFile(path))) {
            ++scanned;
            if (carriesASideEffect(condition)) {
                offences.push_back(path.generic_string() + ": " + condition);
            }
        }
    }

    RecordProperty("scannedAssertionConditions", static_cast<int>(scanned));
    EXPECT_TRUE(offences.empty()) << "an assertion condition carries an effect the shipping configuration drops: "
                                  << (offences.empty() ? std::string{} : offences.front());
}
