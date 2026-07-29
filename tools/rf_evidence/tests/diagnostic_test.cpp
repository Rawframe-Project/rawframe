#include "diagnostic.h"
#include "failure.h"

#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <set>
#include <simdjson.h>
#include <sstream>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

namespace {

constexpr std::array kAllFailureCodes = {
    FailureCode::InvalidArguments,
    FailureCode::InvalidJson,
    FailureCode::InvalidManifest,
    FailureCode::InvalidPath,
    FailureCode::IoFailure,
    FailureCode::LimitExceeded,
    FailureCode::MissingInput,
    FailureCode::OwnershipCollision,
    FailureCode::UnsupportedHost,
    FailureCode::VerificationFailed,
};

std::string escaped(std::string_view value) {
    std::ostringstream output;
    writeJsonString(output, value);
    return output.str();
}

std::string rendered(const Failure& failure, OutputFormat format) {
    std::ostringstream output;
    renderFailure(output, failure, format);
    return output.str();
}

// The tool builds with exceptions disabled, so simdjson results are unwrapped
// through the error-returning accessor rather than through `value()`.
std::string stringField(simdjson::dom::element root, std::string_view key) {
    std::string_view value;
    EXPECT_EQ(root.at_key(key).get_string().get(value), 0) << "missing string member: " << key;
    return std::string{value};
}

bool boolField(simdjson::dom::element root, std::string_view key) {
    bool value = false;
    EXPECT_EQ(root.at_key(key).get_bool().get(value), 0) << "missing boolean member: " << key;
    return value;
}

} // namespace

// A typed failure is only typed if it survives to the machine-readable stream
// as itself. Two codes sharing a name would silently merge two contract
// failures into one observation.
TEST(Diagnostic, GivesEveryFailureCodeADistinctStableName) {
    std::set<std::string_view> names;
    for (const auto kCode : kAllFailureCodes) {
        const std::string_view kName = failureCodeName(kCode);
        EXPECT_FALSE(kName.empty());
        EXPECT_NE(kName, "unknown_failure") << "a declared code fell through to the fallback name";
        EXPECT_TRUE(names.insert(kName).second) << "duplicate failure code name: " << kName;
    }
    EXPECT_EQ(names.size(), kAllFailureCodes.size());
}

TEST(Diagnostic, EscapesEveryStructuralCharacter) {
    EXPECT_EQ(escaped("a\"b"), "\"a\\\"b\"");
    EXPECT_EQ(escaped("a\\b"), "\"a\\\\b\"");
    EXPECT_EQ(escaped("a\bb"), "\"a\\bb\"");
    EXPECT_EQ(escaped("a\fb"), "\"a\\fb\"");
    EXPECT_EQ(escaped("a\nb"), "\"a\\nb\"");
    EXPECT_EQ(escaped("a\rb"), "\"a\\rb\"");
    EXPECT_EQ(escaped("a\tb"), "\"a\\tb\"");
}

// A control character below 0x20 with no short escape must use the six
// character form, and no raw control byte may survive into the record. The
// boundary matters: 0x1f is escaped and 0x20 is a literal space.
TEST(Diagnostic, EscapesControlCharactersAtTheBoundary) {
    EXPECT_EQ(escaped(std::string_view{"\x01", 1U}), "\"\\u0001\"");
    EXPECT_EQ(escaped(std::string_view{"\x1f", 1U}), "\"\\u001f\"");
    EXPECT_EQ(escaped(std::string_view{"\x20", 1U}), "\" \"");

    for (unsigned char byte = 0U; byte < 0x20U; ++byte) {
        const auto kText = escaped(std::string_view{reinterpret_cast<const char*>(&byte), 1U});
        const auto kRaw = std::ranges::find_if(kText, [](unsigned char character) {
            return character < 0x20U;
        });
        EXPECT_EQ(kRaw, kText.end()) << "raw control byte survived escaping: " << static_cast<int>(byte);
    }
}

// JSON requires no escape above 0x1f other than the quote and the backslash,
// and the encoding is UTF-8, so multibyte text passes through unaltered.
TEST(Diagnostic, PassesUtf8TextThroughUnescaped) {
    EXPECT_EQ(escaped("olcum"), "\"olcum\"");
    EXPECT_EQ(escaped("\xC3\xB6\xC3\xA7"), "\"\xC3\xB6\xC3\xA7\"");
    EXPECT_EQ(escaped(std::string_view{"\x7f", 1U}), "\"\x7f\"");
}

TEST(Diagnostic, EmitsATypedFailureAsParseableJson) {
    const Failure kFailure{FailureCode::LimitExceeded, "tools/rf_evidence/tool.json", "file exceeds its byte limit"};
    const auto kText = rendered(kFailure, OutputFormat::Json);

    simdjson::dom::parser parser;
    simdjson::dom::element root;
    ASSERT_EQ(parser.parse(simdjson::padded_string(kText)).get(root), 0);
    EXPECT_FALSE(boolField(root, "ok"));
    EXPECT_EQ(stringField(root, "code"), "limit_exceeded");
    EXPECT_EQ(stringField(root, "path"), "tools/rf_evidence/tool.json");
    EXPECT_EQ(stringField(root, "message"), "file exceeds its byte limit");
}

// A path or message carrying a quote, a backslash, a newline, or a control
// byte is the case that breaks a machine-readable stream. It must remain one
// parseable record whose decoded fields equal the originals exactly.
TEST(Diagnostic, KeepsHostileTextInsideOneParseableRecord) {
    const Failure kFailure{FailureCode::InvalidPath, "a\"b\\c\nd", "line one\nline\ttwo\x01"};
    const auto kText = rendered(kFailure, OutputFormat::Json);

    simdjson::dom::parser parser;
    simdjson::dom::element root;
    ASSERT_EQ(parser.parse(simdjson::padded_string(kText)).get(root), 0);
    EXPECT_EQ(stringField(root, "path"), kFailure.path);
    EXPECT_EQ(stringField(root, "message"), kFailure.message);
}

TEST(Diagnostic, EmitsSuccessAsParseableJsonMarkedDistinctlyFromFailure) {
    std::ostringstream output;
    renderSuccess(output, "repository", "3 tools", OutputFormat::Json);

    simdjson::dom::parser parser;
    simdjson::dom::element root;
    ASSERT_EQ(parser.parse(simdjson::padded_string(output.str())).get(root), 0);
    EXPECT_TRUE(boolField(root, "ok"));
    EXPECT_EQ(stringField(root, "operation"), "repository");
    EXPECT_EQ(stringField(root, "details"), "3 tools");
}

TEST(Diagnostic, NamesTheTypedCodeInHumanOutput) {
    const Failure kFailure{FailureCode::OwnershipCollision, "repository.json", "two tools claim one root"};
    const auto kText = rendered(kFailure, OutputFormat::Human);
    EXPECT_NE(kText.find("ownership_collision"), std::string::npos);
    EXPECT_NE(kText.find("repository.json"), std::string::npos);
    EXPECT_NE(kText.find("two tools claim one root"), std::string::npos);
    EXPECT_TRUE(kText.ends_with("\n"));
}

// Human output is a rendering, not a second record format. It must never be
// mistaken for the machine-readable stream by a caller reading either one.
TEST(Diagnostic, KeepsHumanOutputDistinctFromTheJsonRecord) {
    const Failure kFailure{FailureCode::IoFailure, "out/cache", "failed to open file"};
    EXPECT_EQ(rendered(kFailure, OutputFormat::Human).find('{'), std::string::npos);
    EXPECT_TRUE(rendered(kFailure, OutputFormat::Json).starts_with("{"));
}

TEST(Diagnostic, EmitsExactlyOneRecordPerRenderedFailure) {
    const Failure kFailure{FailureCode::MissingInput, "third_party/catalog.json", "file is missing or unreadable"};
    for (const auto kFormat : {OutputFormat::Human, OutputFormat::Json}) {
        const auto kText = rendered(kFailure, kFormat);
        EXPECT_EQ(std::ranges::count(kText, '\n'), 1) << "a rendered failure must be one line";
    }
}

} // namespace rawframe::tool::evidence
