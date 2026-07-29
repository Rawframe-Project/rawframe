#pragma once

#include "failure.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rawframe::tool::evidence {

// SPEC-0017 bounds. A record is small by construction; these exist so a hostile
// input is refused before the work rather than after it.
inline constexpr std::size_t kMaximumRecordBytes = 1'048'576;
inline constexpr std::size_t kMaximumRecordDepth = 32;
inline constexpr std::size_t kMaximumRecordNodes = 65'536;
inline constexpr std::size_t kMaximumRecordStringBytes = 4'096;
inline constexpr std::size_t kMaximumRecordMembers = 4'096;

// Why a record was refused.
//
// Deliberately not folded into FailureCode: these are record-domain outcomes a
// caller distinguishes and a test asserts separately, and mapping them onto the
// tool-wide list would make "this is not the canonical form of itself" and "the
// schema refuses this" the same answer.
enum class RecordRejection : std::uint8_t {
    MalformedInput,
    NoncanonicalBytes,
    SchemaInvalid,
    DescriptorMismatch,
    LimitExceeded,
};

[[nodiscard]] constexpr const char* recordRejectionName(RecordRejection rejection) noexcept {
    switch (rejection) {
    case RecordRejection::MalformedInput:
        return "malformed_input";
    case RecordRejection::NoncanonicalBytes:
        return "noncanonical_bytes";
    case RecordRejection::SchemaInvalid:
        return "schema_invalid";
    case RecordRejection::DescriptorMismatch:
        return "descriptor_mismatch";
    case RecordRejection::LimitExceeded:
        return "limit_exceeded";
    }
    return "unknown_rejection";
}

struct RecordFailure {
    RecordRejection rejection;
    std::string detail;
};

template <typename ValueType> using RecordResult = std::expected<ValueType, RecordFailure>;
using RecordStatus = RecordResult<void>;

// A value inside SPEC-0017's accepted subset. There is no floating-point kind,
// because the subset has no floating-point values: a fractional quantity is
// carried by an integer and a scale exponent so that its bytes are exact.
class CanonicalValue {
public:
    enum class Kind : std::uint8_t {
        Null,
        Boolean,
        Integer,
        String,
        Array,
        Object
    };

    using Member = std::pair<std::string, CanonicalValue>;

    CanonicalValue() = default;

    [[nodiscard]] static CanonicalValue makeNull();
    [[nodiscard]] static CanonicalValue makeBoolean(bool value);
    [[nodiscard]] static CanonicalValue makeInteger(std::int64_t value);
    [[nodiscard]] static CanonicalValue makeString(std::string value);
    [[nodiscard]] static CanonicalValue makeArray(std::vector<CanonicalValue> elements);

    // Members are stored in canonical order, so construction sorts them and
    // there is no later moment at which an unsorted object could be serialized.
    [[nodiscard]] static CanonicalValue makeObject(std::vector<Member> members);

    [[nodiscard]] Kind kind() const noexcept {
        return kind_;
    }
    [[nodiscard]] bool boolean() const noexcept {
        return boolean_;
    }
    [[nodiscard]] std::int64_t integer() const noexcept {
        return integer_;
    }
    [[nodiscard]] const std::string& text() const noexcept {
        return text_;
    }
    [[nodiscard]] const std::vector<CanonicalValue>& elements() const noexcept {
        return elements_;
    }
    [[nodiscard]] const std::vector<Member>& members() const noexcept {
        return members_;
    }

    // Nullptr when absent. Members are sorted, so this is a binary search.
    [[nodiscard]] const CanonicalValue* find(std::string_view name) const noexcept;

private:
    Kind kind_ = Kind::Null;
    bool boolean_ = false;
    std::int64_t integer_ = 0;
    std::string text_;
    std::vector<CanonicalValue> elements_;
    std::vector<Member> members_;
};

// RFC 8785 member ordering: by UTF-16 code unit, which differs from code point
// order above the basic multilingual plane.
[[nodiscard]] bool jcsKeyLess(std::string_view left, std::string_view right);

// Parse strictly. Rejects everything outside the accepted subset, including a
// number whose lexical form is not a bare integer, before any value is built.
[[nodiscard]] RecordResult<CanonicalValue> parseCanonicalSubset(std::string_view bytes);

// The canonical bytes of a value: JCS ordering, minimal escaping, no
// whitespace, no trailing newline.
[[nodiscard]] std::string serializeCanonical(const CanonicalValue& value);

// Parse claimed-canonical bytes and prove they are the canonical form of
// themselves. Never returns a corrected form, because a caller holding one
// would eventually write it somewhere.
[[nodiscard]] RecordResult<CanonicalValue> ingestCanonicalBytes(std::string_view claimed);

} // namespace rawframe::tool::evidence
