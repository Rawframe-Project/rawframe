#include "json_reader.h"
#include "tool_limits.h"

#include <gtest/gtest.h>
#include <string>

namespace rawframe::tool::archcheck {

TEST(JsonReader, KeepsMemberOrderRatherThanSortingIt) {
    auto parsed = parseJson(R"({"zebra":1,"alpha":2})");
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->members.size(), 2U);
    EXPECT_EQ(parsed->members.at(0).first, "zebra");
    EXPECT_EQ(parsed->members.at(1).first, "alpha");
}

TEST(JsonReader, KeepsANumericLiteralAsItWasWritten) {
    auto parsed = parseJson(R"({"value":1.50})");
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->members.size(), 1U);
    EXPECT_EQ(parsed->members.at(0).second.kind, JsonKind::Number);
    EXPECT_EQ(parsed->members.at(0).second.text, "1.50");
}

TEST(JsonReader, RefusesADuplicateMemberRatherThanKeepingOne) {
    auto parsed = parseJson(R"({"a":1,"a":2})");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, FailureCode::InvalidJson);
}

TEST(JsonReader, RefusesNestingBeyondTheDepthCeiling) {
    std::string document;
    for (std::size_t index = 0; index <= kMaximumJsonDepth + 2; ++index) {
        document += "[";
    }
    document += "1";
    for (std::size_t index = 0; index <= kMaximumJsonDepth + 2; ++index) {
        document += "]";
    }
    auto parsed = parseJson(document);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, FailureCode::LimitExceeded);
}

TEST(JsonReader, RoundTripsTheMaintainedFormOfADocumentThatIsAlreadyInIt) {
    const std::string kDocument = "{\n  \"a\": [\n    1,\n    2\n  ],\n  \"b\": {\n    \"c\": true\n  }\n}";
    auto parsed = parseJson(kDocument);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(serializeMaintainedForm(*parsed), kDocument);
}

TEST(JsonReader, RendersAnEmptyCollectionWithoutOpeningALine) {
    auto parsed = parseJson(R"({"a":[],"b":{}})");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(serializeMaintainedForm(*parsed), "{\n  \"a\": [],\n  \"b\": {}\n}");
}

TEST(JsonReader, EscapesTheCharactersJsonRequiresAndLeavesTheRestAlone) {
    auto parsed = parseJson(R"({"a":"one\ttwo\"three\\four"})");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(serializeMaintainedForm(*parsed), "{\n  \"a\": \"one\\ttwo\\\"three\\\\four\"\n}");
}

TEST(JsonReader, ReportsAnAbsentFileAsMissingInputRatherThanAsMalformed) {
    auto document = readJsonDocument(std::filesystem::path("no-such-file-anywhere.json"));
    ASSERT_FALSE(document.has_value());
    EXPECT_NE(document.error().code, FailureCode::InvalidJson);
}

} // namespace rawframe::tool::archcheck
