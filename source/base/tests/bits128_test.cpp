// SPEC-0046 conformance items 14 through 17.

#include "rawframe/base/bits128.h"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace {

using rawframe::base::Bits128;
using rawframe::base::formatBits128Hex;
using rawframe::base::kBits128HexDigits;
using rawframe::base::parseBits128Hex;

/// The canonical text of a value, as a string the tests can compare and print.
std::string canonicalText(const Bits128& value) {
    std::array<char, kBits128HexDigits> digits{};
    formatBits128Hex(value, std::span<char, kBits128HexDigits>{digits});
    return std::string{digits.data(), digits.size()};
}

/// A corpus that isolates each member and crosses the boundary between them.
/// A shallower corpus cannot see a member-order mistake, which is the defect
/// item 15 exists to catch.
const std::vector<Bits128>& corpus() {
    static const std::vector<Bits128> kValues{
        Bits128{0, 0},
        Bits128{0, 1},
        Bits128{0, 0xFFFFFFFFFFFFFFFFULL},
        Bits128{1, 0},
        Bits128{1, 0xFFFFFFFFFFFFFFFFULL},
        Bits128{0xFFFFFFFFFFFFFFFFULL, 0},
        Bits128{0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL},
        Bits128{0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL},
        Bits128{0x00000000FFFFFFFFULL, 0xFFFFFFFF00000000ULL},
        Bits128{0x8000000000000000ULL, 0x0000000000000001ULL},
    };
    return kValues;
}

} // namespace

// Item 14.
TEST(Bits128, FormatThenParseReturnsTheOriginalValue) {
    RecordProperty("requirement", "SPEC-0046:item-14-hex-round-trip");

    for (const Bits128& value : corpus()) {
        const std::string kText = canonicalText(value);
        ASSERT_EQ(kText.size(), kBits128HexDigits) << "format wrote the wrong number of digits";
        const auto kParsed = parseBits128Hex(kText);
        EXPECT_TRUE(kParsed.parsed) << "the canonical form of " << kText << " did not parse";
        EXPECT_EQ(kParsed.value, value) << "round trip changed the value at " << kText;
    }
}

TEST(Bits128, FormatsOnlyLowercaseCanonicalDigits) {
    RecordProperty("requirement", "SPEC-0046:item-14-hex-round-trip");

    for (const Bits128& value : corpus()) {
        for (const char kDigit : canonicalText(value)) {
            const bool kCanonical = (kDigit >= '0' && kDigit <= '9') || (kDigit >= 'a' && kDigit <= 'f');
            EXPECT_TRUE(kCanonical) << "format produced a non-canonical digit: " << kDigit;
        }
    }
}

// Item 15. Member order fixes sort order, and SPEC-0046 makes the equivalence
// between value order and text order something callers may rely on.
TEST(Bits128, OrderingMatchesLexicographicOrderingOfTheCanonicalText) {
    RecordProperty("requirement", "SPEC-0046:item-15-ordering-matches-text");

    const std::vector<Bits128>& values = corpus();
    for (const Bits128& left : values) {
        for (const Bits128& right : values) {
            const auto kValueOrder = left <=> right;
            const auto kTextOrder = canonicalText(left) <=> canonicalText(right);
            EXPECT_EQ(kValueOrder == std::strong_ordering::less, kTextOrder == std::strong_ordering::less)
                << canonicalText(left) << " and " << canonicalText(right) << " disagree on order";
            EXPECT_EQ(left == right, canonicalText(left) == canonicalText(right))
                << canonicalText(left) << " and " << canonicalText(right) << " disagree on equality";
        }
    }
}

TEST(Bits128, OrdersTheHighMemberAboveTheLowMember) {
    RecordProperty("requirement", "SPEC-0046:item-15-ordering-matches-text");

    // The one comparison a reversed member order would get backwards: a larger
    // low half must not outrank a larger high half.
    EXPECT_LT((Bits128{0, 0xFFFFFFFFFFFFFFFFULL}), (Bits128{1, 0}));
}

// Item 16. Every rejection SPEC-0046 names, each proved to return a false flag
// and a zero value rather than asserting or terminating.
TEST(Bits128, RejectsEverythingButTheCanonicalForm) {
    RecordProperty("requirement", "SPEC-0046:item-16-parse-rejections");

    const std::vector<std::pair<std::string_view, std::string_view>> kRejections{
        {"empty", ""},
        {"too short", "0123456789abcdef0123456789abcde"},
        {"too long", "0123456789abcdef0123456789abcdef0"},
        {"uppercase digits", "0123456789ABCDEF0123456789abcdef"},
        {"a 0x prefix", "0x123456789abcdef0123456789abcde"},
        {"an embedded separator", "0123456789abcdef-123456789abcdef"},
        {"leading whitespace", " 123456789abcdef0123456789abcdef"},
        {"trailing whitespace", "0123456789abcdef0123456789abcde "},
        {"a non-hexadecimal first character", "g123456789abcdef0123456789abcdef"},
        {"a non-hexadecimal last character", "0123456789abcdef0123456789abcdeg"},
        {"an embedded null", std::string_view{"0123456789abcdef0123456789abcd\0f", 32}},
    };

    for (const auto& [description, text] : kRejections) {
        const auto kParsed = parseBits128Hex(text);
        EXPECT_FALSE(kParsed.parsed) << "parsing accepted " << description;
        EXPECT_EQ(kParsed.value, (Bits128{0, 0})) << "a rejected parse produced a value for " << description;
    }
}

TEST(Bits128, AcceptsTheCanonicalFormOfEveryCorpusValue) {
    RecordProperty("requirement", "SPEC-0046:item-16-parse-rejections");

    // The other half of the rejection corpus: a parser that rejects everything
    // would pass the test above and fail this one.
    for (const Bits128& value : corpus()) {
        EXPECT_TRUE(parseBits128Hex(canonicalText(value)).parsed);
    }
}

// Item 17. Both operations evaluate in a constant expression, which is what makes
// a schema-generated identity constant a compile-time value rather than static
// initialization work.
namespace {

constexpr bool roundTripsInAConstantExpression(const Bits128& value) {
    std::array<char, kBits128HexDigits> digits{};
    formatBits128Hex(value, std::span<char, kBits128HexDigits>{digits});
    const auto kParsed = parseBits128Hex(std::string_view{digits.data(), digits.size()});
    return kParsed.parsed && kParsed.value == value;
}

static_assert(roundTripsInAConstantExpression(Bits128{0, 0}));
static_assert(roundTripsInAConstantExpression(Bits128{0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL}));
static_assert(roundTripsInAConstantExpression(Bits128{0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL}));
static_assert(!parseBits128Hex("").parsed);
static_assert(parseBits128Hex("0123456789abcdef0123456789abcdef").value.high == 0x0123456789ABCDEFULL);

} // namespace

TEST(Bits128, EvaluatesInAConstantExpression) {
    RecordProperty("requirement", "SPEC-0046:item-17-constexpr-evaluation");

    // The proof is the static_asserts above, which are checked at compile time.
    // This case exists so the requirement has a test to bind to and so a reader
    // of the report finds the item rather than an absence.
    static_assert(roundTripsInAConstantExpression(Bits128{1, 0}));
    SUCCEED();
}

// The hash specialization exists to make lookup work. Its value is unspecified,
// so the only thing worth asserting is that it is usable and that equal values
// find each other.
TEST(Bits128, IsUsableAsAStandardAssociativeKey) {
    std::unordered_map<Bits128, int> byValue;
    int ordinal = 0;
    for (const Bits128& kValue : corpus()) {
        byValue.emplace(kValue, ordinal);
        ++ordinal;
    }
    EXPECT_EQ(byValue.size(), corpus().size());

    ordinal = 0;
    for (const Bits128& kValue : corpus()) {
        EXPECT_EQ(byValue.at(kValue), ordinal);
        ++ordinal;
    }
}
