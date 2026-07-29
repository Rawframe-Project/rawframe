#include "canonical_json.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

namespace {

RecordRejection rejectionOf(std::string_view bytes) {
    auto result = ingestCanonicalBytes(bytes);
    EXPECT_FALSE(result.has_value()) << "expected a rejection for: " << bytes;
    if (result) {
        return RecordRejection::MalformedInput;
    }
    return result.error().rejection;
}

std::string detailOf(std::string_view bytes) {
    auto result = ingestCanonicalBytes(bytes);
    EXPECT_FALSE(result.has_value()) << "expected a rejection for: " << bytes;
    if (result) {
        return {};
    }
    return result.error().detail;
}

std::string canonicalOf(std::string_view bytes) {
    auto parsed = parseCanonicalSubset(bytes);
    EXPECT_TRUE(parsed.has_value()) << (parsed ? std::string{} : parsed.error().detail);
    if (!parsed) {
        return {};
    }
    return serializeCanonical(*parsed);
}

// Every rejection case below mutates one thing about this document. Without it,
// a rejection case would pass just as well if the parser had collapsed
// entirely, which is the failure mode a negative corpus hides best.
constexpr std::string_view kCanonical = R"({"a":1,"b":[true,false,null],"c":{"d":-7,"e":"x"}})";

std::string readVector(std::string_view name) {
    const std::filesystem::path kPath = std::filesystem::path(RAWFRAME_TEST_REPOSITORY_ROOT) /
                                        "tools/rf_evidence/tests/fixtures/evidence/rfc8785" / name;
    std::ifstream input(kPath, std::ios::binary);
    EXPECT_TRUE(input.is_open()) << "missing vector: " << name;
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

std::string nested(std::size_t levels) {
    std::string text;
    for (std::size_t index = 0; index < levels; ++index) {
        text += R"({"a":)";
    }
    text += "1";
    text.append(levels, '}');
    return text;
}

std::string objectWithMembers(std::size_t count) {
    std::string text = "{";
    for (std::size_t index = 0; index < count; ++index) {
        if (index != 0) {
            text += ",";
        }
        std::string name = std::to_string(index);
        text += "\"m" + std::string(6 - name.size(), '0') + name + "\":1";
    }
    text += "}";
    return text;
}

std::string arrayWithElements(std::size_t count) {
    std::string text = R"({"a":[)";
    for (std::size_t index = 0; index < count; ++index) {
        if (index != 0) {
            text += ",";
        }
        text += "1";
    }
    text += "]}";
    return text;
}

} // namespace

TEST(CanonicalJson, AcceptsTheUnmutatedCanonicalDocument) {
    auto result = ingestCanonicalBytes(kCanonical);
    ASSERT_TRUE(result.has_value()) << (result ? std::string{} : result.error().detail);
    EXPECT_EQ(serializeCanonical(*result), kCanonical);
}

TEST(CanonicalJson, OrdersMembersByCodeUnitRegardlessOfInputOrder) {
    EXPECT_EQ(canonicalOf(R"({"b":1,"a":2})"), R"({"a":2,"b":1})");
    EXPECT_EQ(canonicalOf(R"({"B":1,"a":2})"), R"({"B":1,"a":2})");
    EXPECT_EQ(canonicalOf(R"({"a10":1,"a2":2})"), R"({"a10":1,"a2":2})");
}

// RFC 8785 orders by UTF-16 code unit, not by code point. A character above the
// basic multilingual plane becomes a surrogate pair, which sorts below U+E000
// even though its code point is far above it.
TEST(CanonicalJson, OrdersAstralKeysBelowHighBasicMultilingualPlaneKeys) {
    EXPECT_TRUE(jcsKeyLess("\xF0\x9F\x98\x80", "\xEE\x80\x80"));
    EXPECT_FALSE(jcsKeyLess("\xEE\x80\x80", "\xF0\x9F\x98\x80"));
    EXPECT_TRUE(jcsKeyLess("a", "b"));
    EXPECT_FALSE(jcsKeyLess("a", "a"));
    EXPECT_TRUE(jcsKeyLess("a", "aa"));
}

TEST(CanonicalJson, RejectsBytesThatAreNotTheirOwnCanonicalForm) {
    EXPECT_EQ(rejectionOf(R"({"b":1,"a":2})"), RecordRejection::NoncanonicalBytes);
    EXPECT_EQ(rejectionOf("{\"a\": 1}"), RecordRejection::NoncanonicalBytes);
    EXPECT_EQ(rejectionOf("{\"a\":1}\n"), RecordRejection::MalformedInput);
    EXPECT_EQ(rejectionOf(" {\"a\":1}"), RecordRejection::MalformedInput);
}

TEST(CanonicalJson, RejectsAByteOrderMark) {
    EXPECT_EQ(rejectionOf("\xEF\xBB\xBF{\"a\":1}"), RecordRejection::MalformedInput);
    EXPECT_NE(detailOf("\xEF\xBB\xBF{\"a\":1}").find("byte order mark"), std::string::npos);
}

TEST(CanonicalJson, RejectsADuplicateDecodedMemberName) {
    EXPECT_EQ(rejectionOf(R"({"a":1,"a":2})"), RecordRejection::MalformedInput);
    EXPECT_NE(detailOf(R"({"a":1,"a":2})").find("duplicate decoded member"), std::string::npos);
    // The duplicate is only visible after unescaping, which is where a parser
    // comparing raw key bytes would let it through.
    EXPECT_EQ(rejectionOf(R"({"a":1,"a":2})"), RecordRejection::MalformedInput);
}

// The gate the schema oracle cannot supply. JSON Schema accepts all of these
// against a schema requiring an integer, because its integer type constrains
// the value and not the token.
TEST(CanonicalJson, RejectsANumberWhoseLexicalFormIsNotABareInteger) {
    EXPECT_EQ(rejectionOf(R"({"a":1.0})"), RecordRejection::MalformedInput);
    EXPECT_NE(detailOf(R"({"a":1.0})").find("fraction"), std::string::npos);
    EXPECT_EQ(rejectionOf(R"({"a":1e2})"), RecordRejection::MalformedInput);
    EXPECT_NE(detailOf(R"({"a":1e2})").find("exponent"), std::string::npos);
    EXPECT_EQ(rejectionOf(R"({"a":1E2})"), RecordRejection::MalformedInput);
    EXPECT_EQ(rejectionOf(R"({"a":-0})"), RecordRejection::MalformedInput);
    EXPECT_NE(detailOf(R"({"a":-0})").find("negative zero"), std::string::npos);
    EXPECT_EQ(rejectionOf(R"({"a":01})"), RecordRejection::MalformedInput);
}

TEST(CanonicalJson, AcceptsIntegersAtAndRejectsIntegersBeyondTheSafeRange) {
    EXPECT_TRUE(ingestCanonicalBytes(R"({"a":9007199254740991})").has_value());
    EXPECT_TRUE(ingestCanonicalBytes(R"({"a":-9007199254740991})").has_value());
    EXPECT_EQ(rejectionOf(R"({"a":9007199254740992})"), RecordRejection::LimitExceeded);
    EXPECT_EQ(rejectionOf(R"({"a":-9007199254740992})"), RecordRejection::LimitExceeded);
}

TEST(CanonicalJson, RejectsMalformedUtf8AndEncodedSurrogates) {
    EXPECT_EQ(rejectionOf("{\"a\":\"\xC3\x28\"}"), RecordRejection::MalformedInput);
    EXPECT_FALSE(parseCanonicalSubset(R"({"a":"\uD800"})").has_value());
    EXPECT_FALSE(parseCanonicalSubset(R"({"a":"\uDC00\uD800"})").has_value());
    // A well-formed pair is a real character and stays admitted.
    EXPECT_TRUE(parseCanonicalSubset("{\"a\":\"\xF0\x9F\x98\x80\"}").has_value());
}

TEST(CanonicalJson, EscapesOnlyWhatRfc8785Escapes) {
    EXPECT_EQ(canonicalOf(R"({"a":"A"})"), R"({"a":"A"})");
    EXPECT_EQ(canonicalOf(R"({"a":"\/"})"), R"({"a":"/"})");
    EXPECT_EQ(canonicalOf(R"({"a":""})"), R"({"a":""})");
    EXPECT_EQ(canonicalOf(R"({"a":"\t\n\r\b\f"})"), R"({"a":"\t\n\r\b\f"})");
    // A control character below U+0020 has no short form, so it keeps the
    // six-character escape. U+007F is not a control character to RFC 8785 and
    // stays literal, which is the pair a hand-written escaper gets backwards.
    EXPECT_EQ(canonicalOf("{\"a\":\"\\u0001\"}"), "{\"a\":\"\\u0001\"}");
    EXPECT_EQ(canonicalOf("{\"a\":\"\\u007f\"}"), "{\"a\":\"\x7F\"}");
    EXPECT_EQ(canonicalOf("{\"a\":\"\xC3\xA9\"}"), "{\"a\":\"\xC3\xA9\"}");
    EXPECT_EQ(canonicalOf(R"({"a":"é"})"), "{\"a\":\"\xC3\xA9\"}");
}

TEST(CanonicalJson, RejectsTrailingContentAfterTheRecord) {
    EXPECT_EQ(rejectionOf(R"({"a":1}{"b":2})"), RecordRejection::MalformedInput);
    EXPECT_EQ(rejectionOf(R"({"a":1} )"), RecordRejection::MalformedInput);
}

TEST(CanonicalJson, RejectsATopLevelValueThatIsNotAnObject) {
    EXPECT_EQ(rejectionOf("[1,2]"), RecordRejection::MalformedInput);
    EXPECT_EQ(rejectionOf("1"), RecordRejection::MalformedInput);
    EXPECT_EQ(rejectionOf(R"("a")"), RecordRejection::MalformedInput);
    EXPECT_EQ(rejectionOf(""), RecordRejection::MalformedInput);
}

// The published RFC 8785 vectors, restricted to the accepted subset. The
// document's own sample carries fractions and exponents, so only its string
// member survives the restriction; the sorting vector survives whole. Each
// golden file is also its own canonical form, which is the second half of the
// claim and the half a one-directional comparison would miss.
TEST(CanonicalJson, MatchesThePublishedRfc8785Vectors) {
    for (const std::string_view kStem : {"sorting", "strings", "literals", "name-order"}) {
        const std::string kInput = readVector(std::string(kStem) + ".input.json");
        const std::string kGolden = readVector(std::string(kStem) + ".canonical.json");
        EXPECT_EQ(canonicalOf(kInput), kGolden) << kStem;
        EXPECT_TRUE(ingestCanonicalBytes(kGolden).has_value()) << kStem << " golden is not its own canonical form";
    }
}

// Not a Number and the infinities are not JSON, so they are refused before the
// lexical gate ever sees a token. Their string spellings are ordinary strings
// and stay admitted, which is what keeps the rejection about JSON rather than
// about the letters.
TEST(CanonicalJson, RejectsNotANumberAndInfinity) {
    EXPECT_EQ(rejectionOf(R"({"a":NaN})"), RecordRejection::MalformedInput);
    EXPECT_EQ(rejectionOf(R"({"a":Infinity})"), RecordRejection::MalformedInput);
    EXPECT_EQ(rejectionOf(R"({"a":-Infinity})"), RecordRejection::MalformedInput);
    EXPECT_EQ(rejectionOf(R"({"a":1e999})"), RecordRejection::MalformedInput);
    EXPECT_TRUE(ingestCanonicalBytes(R"({"a":"NaN"})").has_value());
}

// Each declared limit at its exact boundary, in both directions. A limit tested
// only from the far side proves the rejection exists but not that it sits where
// the specification puts it.
TEST(CanonicalJson, AdmitsEachLimitAtItsBoundaryAndRejectsOneBeyond) {
    // The limit counts values on the deepest path, and the innermost scalar is
    // one of them, so the boundary is one fewer wrapping object than the number.
    const std::string kAtDepth = nested(kMaximumRecordDepth - 1);
    EXPECT_TRUE(parseCanonicalSubset(kAtDepth).has_value()) << "depth " << kMaximumRecordDepth;
    EXPECT_EQ(rejectionOf(nested(kMaximumRecordDepth)), RecordRejection::LimitExceeded);

    const std::string kAtString = R"({"a":")" + std::string(kMaximumRecordStringBytes, 'x') + R"("})";
    EXPECT_TRUE(parseCanonicalSubset(kAtString).has_value());
    EXPECT_EQ(rejectionOf(R"({"a":")" + std::string(kMaximumRecordStringBytes + 1, 'x') + R"("})"),
              RecordRejection::LimitExceeded);

    EXPECT_TRUE(parseCanonicalSubset(objectWithMembers(kMaximumRecordMembers)).has_value());
    EXPECT_EQ(rejectionOf(objectWithMembers(kMaximumRecordMembers + 1)), RecordRejection::LimitExceeded);

    // The root object and the array are nodes too, so the boundary is two short
    // of the limit rather than at it.
    EXPECT_TRUE(parseCanonicalSubset(arrayWithElements(kMaximumRecordNodes - 2)).has_value());
    EXPECT_EQ(rejectionOf(arrayWithElements(kMaximumRecordNodes - 1)), RecordRejection::LimitExceeded);
}

TEST(CanonicalJson, AdmitsARecordAtTheByteLimitAndRejectsOneBeyondIt) {
    const std::string kOverhead = R"({"a":""})";
    const std::string kAtLimit = R"({"a":")" + std::string(kMaximumRecordBytes - kOverhead.size(), 'x') + R"("})";
    ASSERT_EQ(kAtLimit.size(), kMaximumRecordBytes);
    // The string limit bites first, which is the point: the byte limit is the
    // outer guard and is checked before anything is parsed at all.
    EXPECT_EQ(rejectionOf(kAtLimit), RecordRejection::LimitExceeded);
    EXPECT_NE(detailOf(kAtLimit).find("string"), std::string::npos);
    const std::string kBeyond = kAtLimit + "x";
    EXPECT_NE(detailOf(kBeyond).find("byte limit"), std::string::npos);
}

TEST(CanonicalJson, RejectsNestingBeyondTheDepthLimit) {
    std::string deep;
    for (std::size_t index = 0; index <= kMaximumRecordDepth + 1; ++index) {
        deep += R"({"a":)";
    }
    deep += "1";
    for (std::size_t index = 0; index <= kMaximumRecordDepth + 1; ++index) {
        deep += "}";
    }
    EXPECT_EQ(rejectionOf(deep), RecordRejection::LimitExceeded);
}

TEST(CanonicalJson, RejectsInputBeyondTheByteLimit) {
    std::string large = R"({"a":")";
    large.append(kMaximumRecordBytes + 1, 'x');
    large += R"("})";
    EXPECT_EQ(rejectionOf(large), RecordRejection::LimitExceeded);
}

TEST(CanonicalJson, FindsMembersAndReportsAbsentOnesAsNullptr) {
    auto parsed = parseCanonicalSubset(kCanonical);
    ASSERT_TRUE(parsed.has_value());
    const auto* kFound = parsed->find("a");
    ASSERT_NE(kFound, nullptr);
    EXPECT_EQ(kFound->kind(), CanonicalValue::Kind::Integer);
    EXPECT_EQ(kFound->integer(), 1);
    EXPECT_EQ(parsed->find("zzz"), nullptr);
}

TEST(CanonicalJson, SerializesEachKindInItsCanonicalSpelling) {
    EXPECT_EQ(serializeCanonical(CanonicalValue::makeNull()), "null");
    EXPECT_EQ(serializeCanonical(CanonicalValue::makeBoolean(true)), "true");
    EXPECT_EQ(serializeCanonical(CanonicalValue::makeBoolean(false)), "false");
    EXPECT_EQ(serializeCanonical(CanonicalValue::makeInteger(0)), "0");
    EXPECT_EQ(serializeCanonical(CanonicalValue::makeInteger(-42)), "-42");
    EXPECT_EQ(serializeCanonical(CanonicalValue::makeArray({})), "[]");
    EXPECT_EQ(serializeCanonical(CanonicalValue::makeObject({})), "{}");
}

// Construction sorts, so there is no moment at which an object holding
// out-of-order members could be handed to the serializer.
TEST(CanonicalJson, SortsMembersAtConstructionRatherThanAtSerialization) {
    std::vector<CanonicalValue::Member> members;
    members.emplace_back("b", CanonicalValue::makeInteger(1));
    members.emplace_back("a", CanonicalValue::makeInteger(2));
    const auto kObject = CanonicalValue::makeObject(std::move(members));
    ASSERT_EQ(kObject.members().size(), 2U);
    EXPECT_EQ(kObject.members().front().first, "a");
    EXPECT_EQ(serializeCanonical(kObject), R"({"a":2,"b":1})");
}

// Canonicalizing twice changes nothing. If it ever did, the byte-for-byte
// comparison at the heart of ingest would be comparing against a moving target.
TEST(CanonicalJson, IsIdempotent) {
    const std::string kOnce = canonicalOf(R"({"b":1,"a":{"d":2,"c":[3,{"f":4,"e":5}]}})");
    EXPECT_EQ(canonicalOf(kOnce), kOnce);
    EXPECT_TRUE(ingestCanonicalBytes(kOnce).has_value());
}

} // namespace rawframe::tool::evidence
