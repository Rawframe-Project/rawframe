#include "json_reader.h"
#include "verify_fixture.h"

#include <gtest/gtest.h>
#include <string>

namespace rawframe::tool::verify {

namespace {

std::string nested(std::size_t depth) {
    std::string document;
    for (std::size_t level = 0; level < depth; ++level) {
        document += "[";
    }
    for (std::size_t level = 0; level < depth; ++level) {
        document += "]";
    }
    return document;
}

} // namespace

TEST(JsonReader, ReadsEveryValueKindAndKeepsMemberOrder) {
    auto parsed = parseJson(R"({"b":1,"a":"text","c":[true,false,null],"d":{"e":-3}})");
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    ASSERT_TRUE(parsed->isObject());
    ASSERT_EQ(parsed->members.size(), 4U);
    EXPECT_EQ(parsed->members.at(0).first, "b");
    EXPECT_EQ(parsed->members.at(1).first, "a");

    const JsonNode* text = parsed->find("a");
    ASSERT_NE(text, nullptr);
    ASSERT_TRUE(text->isString());
    EXPECT_EQ(text->text, "text");

    const JsonNode* list = parsed->find("c");
    ASSERT_NE(list, nullptr);
    ASSERT_TRUE(list->isArray());
    ASSERT_EQ(list->elements.size(), 3U);
    EXPECT_TRUE(list->elements.at(0).isBoolean());
    EXPECT_TRUE(list->elements.at(0).boolean);
    EXPECT_FALSE(list->elements.at(1).boolean);
    EXPECT_TRUE(list->elements.at(2).isNull());

    const JsonNode* nestedObject = parsed->find("d");
    ASSERT_NE(nestedObject, nullptr);
    const JsonNode* negative = nestedObject->find("e");
    ASSERT_NE(negative, nullptr);
    auto value = readInteger(*negative);
    ASSERT_TRUE(value.has_value()) << value.error().message;
    EXPECT_EQ(*value, -3);
}

TEST(JsonReader, FindReportsAnAbsentMember) {
    auto parsed = parseJson(R"({"a":1})");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->find("missing"), nullptr);
}

TEST(JsonReader, RejectsADocumentThatIsNotJson) {
    auto parsed = parseJson("{not json");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, FailureCode::InvalidJson);
}

TEST(JsonReader, RejectsADocumentDeeperThanTheNestingLimit) {
    auto parsed = parseJson(nested(200));
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, FailureCode::LimitExceeded);
}

TEST(JsonReader, RejectsAValueThatMustBeAnIntegerAndIsNot) {
    auto parsed = parseJson(R"({"a":"12","b":1.5})");
    ASSERT_TRUE(parsed.has_value());
    const JsonNode* text = parsed->find("a");
    ASSERT_NE(text, nullptr);
    auto fromString = readInteger(*text);
    ASSERT_FALSE(fromString.has_value());
    EXPECT_EQ(fromString.error().code, FailureCode::InvalidJson);

    const JsonNode* fractional = parsed->find("b");
    ASSERT_NE(fractional, nullptr);
    auto fromFraction = readInteger(*fractional);
    ASSERT_FALSE(fromFraction.has_value());
    EXPECT_EQ(fromFraction.error().code, FailureCode::InvalidJson);
}

TEST(JsonReader, RejectsAnArrayPositionThatIsAbsent) {
    auto parsed = parseJson(R"([1,2])");
    ASSERT_TRUE(parsed.has_value());
    auto beyond = readIntegerAt(*parsed, 5);
    ASSERT_FALSE(beyond.has_value());
    EXPECT_EQ(beyond.error().code, FailureCode::InvalidJson);

    auto notAnArray = parseJson(R"({"a":1})");
    ASSERT_TRUE(notAnArray.has_value());
    auto fromObject = readIntegerAt(*notAnArray, 0);
    ASSERT_FALSE(fromObject.has_value());
    EXPECT_EQ(fromObject.error().code, FailureCode::InvalidJson);
}

TEST(JsonReader, ReadsAnArrayPositionThatIsPresent) {
    auto parsed = parseJson(R"([7,8])");
    ASSERT_TRUE(parsed.has_value());
    auto value = readIntegerAt(*parsed, 1);
    ASSERT_TRUE(value.has_value()) << value.error().message;
    EXPECT_EQ(*value, 8);
}

TEST(JsonReader, RejectsAFileThatIsNotThere) {
    auto parsed = readJsonFile(testing::outputRoot() / "absent" / "nothing.json");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, FailureCode::MissingInput);
}

TEST(JsonReader, ReadsAFileAndReportsItsPathOnFailure) {
    const testing::RepositoryFixture kFixture("json_reader_file");
    kFixture.write("out/broken.json", "{oops");
    auto parsed = readJsonFile(kFixture.root() / "out/broken.json");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, FailureCode::InvalidJson);
    EXPECT_NE(parsed.error().path.find("broken.json"), std::string::npos);

    kFixture.write("out/fine.json", R"({"a":1})");
    auto good = readJsonFile(kFixture.root() / "out/fine.json");
    ASSERT_TRUE(good.has_value()) << good.error().message;
    EXPECT_NE(good->find("a"), nullptr);
}

TEST(JsonReader, RefusesANumericLiteralThatIsNotAnInteger) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    auto parsed = parseJson(R"({"a":1.5,"b":1e3})");
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    for (const std::string_view kKey : {"a", "b"}) {
        const JsonNode* node = parsed->find(kKey);
        ASSERT_NE(node, nullptr);
        auto value = readInteger(*node);
        ASSERT_FALSE(value.has_value()) << kKey;
        EXPECT_EQ(value.error().code, FailureCode::InvalidJson) << kKey;
    }
}

TEST(JsonReader, CarriesANestedRejectionOutThroughEveryEnclosingValue) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    std::string document;
    for (std::size_t depth = 0; depth <= 70; ++depth) {
        document += R"({"a":)";
    }
    document += "1";
    for (std::size_t depth = 0; depth <= 70; ++depth) {
        document += "}";
    }
    auto parsed = parseJson(document);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, FailureCode::LimitExceeded);
}

TEST(JsonReader, RefusesAValueTheParserAnnouncesAndThenCannotDeliver) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    // The reader asks for the type of a value before it asks for the value, so
    // the per-kind rejections below are reached only by a document that answers
    // the first question and fails the second. That needs a document whose
    // structure is intact and whose contents are not: a truncated one is refused
    // before any of this runs. Each line names one shape, so a rejection that
    // stopped working would name itself.
    for (const std::string_view kDocument : {
             R"([@])",           // a value of no recognisable kind at all
             R"([tru])",         // announced as a boolean, and not one
             R"([fals])",        // the same, from the other side
             R"(["\q"])",        // announced as a string, with an escape that is not one
             R"({"a":})",        // a member with a key and no value
             R"([{)",            // an object that never closes
             R"([{"a":1)",       // an object whose last member never closes
             R"([[1)",           // an array that never closes
             R"(["abc)",         // a string with no closing quote
             R"([1 2])",         // two array elements with no comma
             R"({"a" 1})",       // an object member with no colon
             R"({"a":1 "b":2})", // two object members with no comma
             R"({1:2})",         // an object key that is not a string
         }) {
        auto parsed = parseJson(kDocument);
        ASSERT_FALSE(parsed.has_value()) << kDocument;
        EXPECT_EQ(parsed.error().code, FailureCode::InvalidJson) << kDocument;
    }
}

TEST(JsonReader, RefusesADocumentWithNothingInItAtAll) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    for (const std::string_view kDocument : {"", "   ", "\n"}) {
        auto parsed = parseJson(kDocument);
        ASSERT_FALSE(parsed.has_value()) << "[" << kDocument << "]";
        EXPECT_EQ(parsed.error().code, FailureCode::InvalidJson);
    }
}

TEST(JsonReader, RefusesAnIntegerLiteralTooLargeForTheTypeThatMustHoldIt) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    // A well-formed JSON number that no signed 64-bit value can represent. The
    // conversion reports a range error rather than stopping early, which is a
    // different rejection from a literal that is simply not an integer.
    auto parsed = parseJson(R"({"a":99999999999999999999999})");
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    const JsonNode* node = parsed->find("a");
    ASSERT_NE(node, nullptr);
    auto value = readInteger(*node);
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().code, FailureCode::InvalidJson);
}

TEST(JsonReader, RefusesAPathThatExistsAndHasNoReadableSize) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    // A directory exists, so the presence test passes, and it has no file size,
    // so the ceiling cannot be applied to it. Reporting that as a read failure
    // is the difference between a refused input and a run that measures nothing
    // and says so in no way at all.
    const testing::RepositoryFixture kFixture("json_directory_input");
    auto read = readJsonFile(kFixture.root() / "tools/subject/src");
    ASSERT_FALSE(read.has_value());
    EXPECT_EQ(read.error().code, FailureCode::IoFailure);
}

} // namespace rawframe::tool::verify
