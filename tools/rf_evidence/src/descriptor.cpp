#include "descriptor.h"

#include "sha256.h"

#include <algorithm>
#include <cctype>

namespace rawframe::tool::evidence {

namespace {

constexpr std::string_view kDigestPrefix = "sha256:";
constexpr std::size_t kDigestHexLength = 64;

std::unexpected<RecordFailure> mismatch(std::string detail) {
    return std::unexpected(RecordFailure{RecordRejection::DescriptorMismatch, std::move(detail)});
}

bool isLowercaseHex(std::string_view text) {
    return std::ranges::all_of(text, [](char character) {
        return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
    });
}

// The algorithm prefix is checked rather than inferred. A bare 64-character
// hex string is the right length for several digests, so accepting one by
// length would silently admit an algorithm nobody chose.
RecordStatus checkDigestForm(std::string_view digest) {
    if (!digest.starts_with(kDigestPrefix)) {
        const auto kSeparator = digest.find(':');
        if (kSeparator == std::string_view::npos) {
            return mismatch("digest carries no algorithm prefix: " + std::string(digest));
        }
        return mismatch("unsupported digest algorithm: " + std::string(digest.substr(0, kSeparator)));
    }
    const auto kHex = digest.substr(kDigestPrefix.size());
    if (kHex.size() != kDigestHexLength) {
        return mismatch("digest is not 64 hexadecimal characters");
    }
    if (!isLowercaseHex(kHex)) {
        return mismatch("digest is not lowercase hexadecimal");
    }
    return {};
}

} // namespace

RecordResult<Descriptor> describeBytes(std::string_view bytes, std::string_view mediaType) {
    if (mediaType.empty()) {
        return mismatch("media type is empty");
    }
    auto digest = sha256Bytes(bytes);
    if (!digest) {
        return mismatch("failed to digest content: " + digest.error().message);
    }
    return Descriptor{std::string(mediaType), bytes.size(), std::string(kDigestPrefix) + *digest};
}

RecordResult<Descriptor> parseDescriptor(const CanonicalValue& value) {
    if (value.kind() != CanonicalValue::Kind::Object) {
        return mismatch("descriptor is not an object");
    }
    if (value.members().size() != 3) {
        return mismatch("descriptor must carry exactly mediaType, byteLength, and digest");
    }
    const auto* kMediaType = value.find("mediaType");
    const auto* kByteLength = value.find("byteLength");
    const auto* kDigest = value.find("digest");
    if (kMediaType == nullptr || kByteLength == nullptr || kDigest == nullptr) {
        return mismatch("descriptor is missing a required member");
    }
    if (kMediaType->kind() != CanonicalValue::Kind::String) {
        return mismatch("descriptor mediaType is not a string");
    }
    if (kDigest->kind() != CanonicalValue::Kind::String) {
        return mismatch("descriptor digest is not a string");
    }
    if (kByteLength->kind() != CanonicalValue::Kind::Integer || kByteLength->integer() < 0) {
        return mismatch("descriptor byteLength is not a non-negative integer");
    }
    if (auto status = checkDigestForm(kDigest->text()); !status) {
        return std::unexpected(status.error());
    }
    return Descriptor{kMediaType->text(), static_cast<std::uint64_t>(kByteLength->integer()), kDigest->text()};
}

RecordStatus
verifyDescriptor(const Descriptor& descriptor, std::string_view bytes, std::string_view expectedMediaType) {
    if (!expectedMediaType.empty() && descriptor.mediaType != expectedMediaType) {
        return mismatch("descriptor media type is " + descriptor.mediaType + ", expected " +
                        std::string(expectedMediaType));
    }
    if (auto status = checkDigestForm(descriptor.digest); !status) {
        return status;
    }
    if (descriptor.byteLength != bytes.size()) {
        return mismatch("descriptor byte length disagrees with the content");
    }
    auto digest = sha256Bytes(bytes);
    if (!digest) {
        return mismatch("failed to digest content: " + digest.error().message);
    }
    if (descriptor.digest != std::string(kDigestPrefix) + *digest) {
        return mismatch("descriptor digest disagrees with the content");
    }
    return {};
}

CanonicalValue describeAsValue(const Descriptor& descriptor) {
    std::vector<CanonicalValue::Member> members;
    members.emplace_back("mediaType", CanonicalValue::makeString(descriptor.mediaType));
    members.emplace_back("byteLength", CanonicalValue::makeInteger(static_cast<std::int64_t>(descriptor.byteLength)));
    members.emplace_back("digest", CanonicalValue::makeString(descriptor.digest));
    return CanonicalValue::makeObject(std::move(members));
}

} // namespace rawframe::tool::evidence
