#include "canonical_json.h"
#include "descriptor.h"

#include <gtest/gtest.h>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

namespace {

// The digest below is this exact byte sequence. Every rejection case mutates
// one field of the descriptor built from it, so a case cannot pass because
// verification stopped working altogether.
constexpr std::string_view kContent = R"({"a":1})";
constexpr std::string_view kContentDigest = "sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862";

Descriptor referenceDescriptor() {
    auto built = describeBytes(kContent, kRawRunReceiptMediaType);
    EXPECT_TRUE(built.has_value());
    return built.value_or(Descriptor{});
}

RecordRejection rejectionOfDescriptorText(std::string_view canonicalDescriptor) {
    auto value = ingestCanonicalBytes(canonicalDescriptor);
    EXPECT_TRUE(value.has_value()) << "the fixture itself must be canonical: " << canonicalDescriptor;
    if (!value) {
        return RecordRejection::MalformedInput;
    }
    auto parsed = parseDescriptor(*value);
    EXPECT_FALSE(parsed.has_value()) << "expected a rejection for: " << canonicalDescriptor;
    if (parsed) {
        return RecordRejection::MalformedInput;
    }
    return parsed.error().rejection;
}

} // namespace

TEST(Descriptor, DescribesContentWithItsExactLengthAndDigest) {
    const auto kDescriptor = referenceDescriptor();
    EXPECT_EQ(kDescriptor.mediaType, kRawRunReceiptMediaType);
    EXPECT_EQ(kDescriptor.byteLength, kContent.size());
    EXPECT_EQ(kDescriptor.digest, kContentDigest);
}

TEST(Descriptor, VerifiesTheUnmutatedDescriptorAgainstItsContent) {
    const auto kDescriptor = referenceDescriptor();
    EXPECT_TRUE(verifyDescriptor(kDescriptor, kContent, kRawRunReceiptMediaType).has_value());
}

TEST(Descriptor, RejectsAByteLengthThatDisagreesWithTheContent) {
    auto descriptor = referenceDescriptor();
    descriptor.byteLength += 1;
    auto status = verifyDescriptor(descriptor, kContent, kRawRunReceiptMediaType);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::DescriptorMismatch);
    EXPECT_NE(status.error().detail.find("byte length"), std::string::npos);
}

TEST(Descriptor, RejectsADigestThatDisagreesWithTheContent) {
    auto descriptor = referenceDescriptor();
    descriptor.digest = "sha256:" + std::string(64, '0');
    auto status = verifyDescriptor(descriptor, kContent, kRawRunReceiptMediaType);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::DescriptorMismatch);
    EXPECT_NE(status.error().detail.find("digest disagrees"), std::string::npos);
}

TEST(Descriptor, RejectsAMediaTypeThatIsNotTheExpectedOne) {
    auto descriptor = referenceDescriptor();
    descriptor.mediaType = "application/json";
    auto status = verifyDescriptor(descriptor, kContent, kRawRunReceiptMediaType);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::DescriptorMismatch);
    EXPECT_NE(status.error().detail.find("media type"), std::string::npos);
}

// A bare hexadecimal string is the right length for more than one digest, so
// admitting one by length would silently accept an algorithm nobody chose.
TEST(Descriptor, RejectsADigestWithNoAlgorithmPrefix) {
    auto descriptor = referenceDescriptor();
    descriptor.digest = std::string(64, 'a');
    auto status = verifyDescriptor(descriptor, kContent, kRawRunReceiptMediaType);
    ASSERT_FALSE(status.has_value());
    EXPECT_NE(status.error().detail.find("no algorithm prefix"), std::string::npos);
}

TEST(Descriptor, RejectsAnUnknownDigestAlgorithm) {
    auto descriptor = referenceDescriptor();
    descriptor.digest = "sha512:" + std::string(64, 'a');
    auto status = verifyDescriptor(descriptor, kContent, kRawRunReceiptMediaType);
    ASSERT_FALSE(status.has_value());
    EXPECT_NE(status.error().detail.find("unsupported digest algorithm"), std::string::npos);
}

TEST(Descriptor, RejectsUppercaseHexadecimal) {
    auto descriptor = referenceDescriptor();
    descriptor.digest = "sha256:" + std::string(64, 'A');
    auto status = verifyDescriptor(descriptor, kContent, kRawRunReceiptMediaType);
    ASSERT_FALSE(status.has_value());
    EXPECT_NE(status.error().detail.find("lowercase"), std::string::npos);
}

TEST(Descriptor, RejectsADigestOfTheWrongLength) {
    auto descriptor = referenceDescriptor();
    descriptor.digest = "sha256:" + std::string(63, 'a');
    EXPECT_FALSE(verifyDescriptor(descriptor, kContent, kRawRunReceiptMediaType).has_value());
    descriptor.digest = "sha256:" + std::string(65, 'a');
    EXPECT_FALSE(verifyDescriptor(descriptor, kContent, kRawRunReceiptMediaType).has_value());
}

TEST(Descriptor, ParsesTheUnmutatedCanonicalDescriptor) {
    const auto kText = serializeCanonical(describeAsValue(referenceDescriptor()));
    auto value = ingestCanonicalBytes(kText);
    ASSERT_TRUE(value.has_value());
    auto parsed = parseDescriptor(*value);
    ASSERT_TRUE(parsed.has_value()) << (parsed ? std::string{} : parsed.error().detail);
    EXPECT_EQ(parsed->digest, kContentDigest);
    EXPECT_EQ(parsed->byteLength, kContent.size());
}

// A descriptor identifies bytes and is never inside them, so a fourth member is
// refused rather than ignored: an extra field is where a self-referential
// digest or a second authority would arrive.
TEST(Descriptor, RejectsADescriptorCarryingAnyAdditionalMember) {
    EXPECT_EQ(
        rejectionOfDescriptorText(
            R"({"byteLength":7,"digest":"sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862","mediaType":"application/json","selfDigest":"sha256:0"})"),
        RecordRejection::DescriptorMismatch);
}

TEST(Descriptor, RejectsADescriptorMissingARequiredMember) {
    EXPECT_EQ(rejectionOfDescriptorText(R"({"byteLength":7,"mediaType":"application/json"})"),
              RecordRejection::DescriptorMismatch);
}

TEST(Descriptor, RejectsAByteLengthThatIsNotANonNegativeInteger) {
    EXPECT_EQ(
        rejectionOfDescriptorText(
            R"({"byteLength":-1,"digest":"sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862","mediaType":"application/json"})"),
        RecordRejection::DescriptorMismatch);
    EXPECT_EQ(
        rejectionOfDescriptorText(
            R"({"byteLength":"7","digest":"sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862","mediaType":"application/json"})"),
        RecordRejection::DescriptorMismatch);
}

TEST(Descriptor, RejectsANonObjectDescriptor) {
    auto value = ingestCanonicalBytes(R"({"a":1})");
    ASSERT_TRUE(value.has_value());
    const auto* kMember = value->find("a");
    ASSERT_NE(kMember, nullptr);
    auto parsed = parseDescriptor(*kMember);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().rejection, RecordRejection::DescriptorMismatch);
}

TEST(Descriptor, RoundTripsThroughItsCanonicalValue) {
    const auto kOriginal = referenceDescriptor();
    auto value = ingestCanonicalBytes(serializeCanonical(describeAsValue(kOriginal)));
    ASSERT_TRUE(value.has_value());
    auto parsed = parseDescriptor(*value);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->mediaType, kOriginal.mediaType);
    EXPECT_EQ(parsed->byteLength, kOriginal.byteLength);
    EXPECT_EQ(parsed->digest, kOriginal.digest);
    EXPECT_TRUE(verifyDescriptor(*parsed, kContent, kRawRunReceiptMediaType).has_value());
}

} // namespace rawframe::tool::evidence
