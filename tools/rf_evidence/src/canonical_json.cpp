#include "canonical_json.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <simdjson.h>
#include <system_error>

namespace rawframe::tool::evidence {

namespace {

std::unexpected<RecordFailure> reject(RecordRejection rejection, std::string detail) {
    return std::unexpected(RecordFailure{rejection, std::move(detail)});
}

// Decode one UTF-8 code point. Returns false on any malformed sequence,
// overlong encoding, or encoded surrogate: this is the only decoder the
// canonical path uses, so a replacement character can never enter a record.
bool decodeCodePoint(std::string_view text, std::size_t& offset, char32_t& codePoint) {
    if (offset >= text.size()) {
        return false;
    }
    const auto kLead = static_cast<unsigned char>(text.at(offset));
    std::size_t extra = 0;
    char32_t value = 0;
    if (kLead < 0x80U) {
        codePoint = kLead;
        offset += 1;
        return true;
    }
    if ((kLead & 0xE0U) == 0xC0U) {
        extra = 1;
        value = kLead & 0x1FU;
    } else if ((kLead & 0xF0U) == 0xE0U) {
        extra = 2;
        value = kLead & 0x0FU;
    } else if ((kLead & 0xF8U) == 0xF0U) {
        extra = 3;
        value = kLead & 0x07U;
    } else {
        return false;
    }
    if (offset + extra >= text.size()) {
        return false;
    }
    for (std::size_t index = 1; index <= extra; ++index) {
        const auto kByte = static_cast<unsigned char>(text.at(offset + index));
        if ((kByte & 0xC0U) != 0x80U) {
            return false;
        }
        value = (value << 6U) | (kByte & 0x3FU);
    }
    // Overlong, surrogate, and out-of-range sequences are all malformed.
    if ((extra == 1 && value < 0x80U) || (extra == 2 && value < 0x800U) || (extra == 3 && value < 0x10000U)) {
        return false;
    }
    if (value > 0x10FFFFU || (value >= 0xD800U && value <= 0xDFFFU)) {
        return false;
    }
    codePoint = value;
    offset += extra + 1;
    return true;
}

// The next UTF-16 code unit, so ordering matches RFC 8785 rather than code
// point order. They differ above the basic multilingual plane, where a
// surrogate pair sorts below U+E000.
bool nextCodeUnit(std::string_view text, std::size_t& offset, std::uint32_t& pending, std::uint32_t& unit) {
    if (pending != 0) {
        unit = pending;
        pending = 0;
        return true;
    }
    char32_t codePoint = 0;
    if (!decodeCodePoint(text, offset, codePoint)) {
        return false;
    }
    if (codePoint < 0x10000U) {
        unit = static_cast<std::uint32_t>(codePoint);
        return true;
    }
    const auto kAdjusted = static_cast<std::uint32_t>(codePoint) - 0x10000U;
    unit = 0xD800U + (kAdjusted >> 10U);
    pending = 0xDC00U + (kAdjusted & 0x3FFU);
    return true;
}

constexpr std::string_view kHexDigits = "0123456789abcdef";

void appendEscapedString(const std::string& text, std::string& output) {
    output.push_back('"');
    for (const char kCharacter : text) {
        const auto kByte = static_cast<unsigned char>(kCharacter);
        switch (kByte) {
        case '"':
            output.append("\\\"");
            continue;
        case '\\':
            output.append("\\\\");
            continue;
        case 0x08U:
            output.append("\\b");
            continue;
        case 0x09U:
            output.append("\\t");
            continue;
        case 0x0AU:
            output.append("\\n");
            continue;
        case 0x0CU:
            output.append("\\f");
            continue;
        case 0x0DU:
            output.append("\\r");
            continue;
        default:
            break;
        }
        if (kByte < 0x20U) {
            output.append("\\u00");
            output.push_back(kHexDigits.at((kByte >> 4U) & 0x0FU));
            output.push_back(kHexDigits.at(kByte & 0x0FU));
            continue;
        }
        output.push_back(kCharacter);
    }
    output.push_back('"');
}

// The lexical gate the schema oracle cannot supply. JSON Schema treats 12250.0,
// 1.225e4, and -0 as the integer 12250, 12250, and 0, because its `integer`
// type constrains the value and not the token. SPEC-0017 constrains the token.
RecordStatus checkIntegerToken(std::string_view token) {
    if (token.empty()) {
        return reject(RecordRejection::MalformedInput, "empty numeric token");
    }
    std::size_t index = 0;
    if (token.front() == '-') {
        index = 1;
        if (token.size() == 1) {
            return reject(RecordRejection::MalformedInput, "numeric token is a bare minus sign");
        }
    }
    if (token.at(index) == '+') {
        return reject(RecordRejection::MalformedInput, "numeric token carries a leading plus: " + std::string(token));
    }
    const std::size_t kFirstDigit = index;
    for (; index < token.size(); ++index) {
        const char kCharacter = token.at(index);
        if (kCharacter == '.') {
            return reject(RecordRejection::MalformedInput, "numeric token carries a fraction: " + std::string(token));
        }
        if (kCharacter == 'e' || kCharacter == 'E') {
            return reject(RecordRejection::MalformedInput, "numeric token carries an exponent: " + std::string(token));
        }
        if (kCharacter < '0' || kCharacter > '9') {
            return reject(RecordRejection::MalformedInput, "numeric token is not an integer: " + std::string(token));
        }
    }
    const auto kDigits = token.substr(kFirstDigit);
    if (kDigits.size() > 1 && kDigits.front() == '0') {
        return reject(RecordRejection::MalformedInput, "numeric token has a leading zero: " + std::string(token));
    }
    if (kFirstDigit == 1 && kDigits == "0") {
        return reject(RecordRejection::MalformedInput, "numeric token is negative zero");
    }
    return {};
}

constexpr std::int64_t kSafeIntegerBound = 9'007'199'254'740'991;

struct Parser {
    std::size_t nodes = 0;

    RecordResult<CanonicalValue> parseValue(simdjson::ondemand::value value, std::size_t depth);
    RecordResult<CanonicalValue> parseObject(simdjson::ondemand::object object, std::size_t depth);
    RecordResult<CanonicalValue> parseArray(simdjson::ondemand::array array, std::size_t depth);
};

RecordResult<CanonicalValue> parseNumber(simdjson::ondemand::value value) {
    // Returned directly rather than through a result: the token is already in
    // the buffer, so there is nothing left that can fail.
    std::string_view token = value.raw_json_token();
    // The token view runs to the next structural character, so it can carry
    // trailing whitespace that belongs to the document rather than the number.
    while (!token.empty() &&
           (token.back() == ' ' || token.back() == '\t' || token.back() == '\n' || token.back() == '\r' ||
            token.back() == ',' || token.back() == '}' || token.back() == ']')) {
        token.remove_suffix(1);
    }
    if (auto status = checkIntegerToken(token); !status) {
        return std::unexpected(status.error());
    }
    std::int64_t parsed = 0;
    const auto kResult = std::from_chars(token.data(), token.data() + token.size(), parsed);
    if (kResult.ec != std::errc{} || kResult.ptr != token.data() + token.size()) {
        return reject(RecordRejection::MalformedInput, "numeric token does not fit an integer: " + std::string(token));
    }
    if (parsed > kSafeIntegerBound || parsed < -kSafeIntegerBound) {
        return reject(RecordRejection::LimitExceeded, "integer outside the safe range: " + std::string(token));
    }
    return CanonicalValue::makeInteger(parsed);
}

RecordResult<CanonicalValue> parseString(simdjson::ondemand::value value) {
    std::string_view text;
    if (const auto kError = value.get_string().get(text); kError) {
        return reject(RecordRejection::MalformedInput,
                      std::string("string is not valid: ") + simdjson::error_message(kError));
    }
    if (text.size() > kMaximumRecordStringBytes) {
        return reject(RecordRejection::LimitExceeded, "string exceeds the record string limit");
    }
    // simdjson unescapes and validates UTF-8, and this second pass is what
    // rejects an encoded surrogate that survived as well-formed bytes.
    std::size_t offset = 0;
    char32_t codePoint = 0;
    while (offset < text.size()) {
        if (!decodeCodePoint(text, offset, codePoint)) {
            return reject(RecordRejection::MalformedInput, "string contains malformed UTF-8 or a surrogate");
        }
    }
    return CanonicalValue::makeString(std::string(text));
}

RecordResult<CanonicalValue> Parser::parseArray(simdjson::ondemand::array array, std::size_t depth) {
    std::vector<CanonicalValue> elements;
    for (auto element : array) {
        simdjson::ondemand::value child;
        if (const auto kError = element.get(child); kError) {
            return reject(RecordRejection::MalformedInput,
                          std::string("malformed array element: ") + simdjson::error_message(kError));
        }
        auto parsed = parseValue(child, depth + 1);
        if (!parsed) {
            return parsed;
        }
        elements.push_back(std::move(*parsed));
    }
    return CanonicalValue::makeArray(std::move(elements));
}

RecordResult<CanonicalValue> Parser::parseObject(simdjson::ondemand::object object, std::size_t depth) {
    std::vector<CanonicalValue::Member> members;
    for (auto field : object) {
        std::string_view key;
        if (const auto kError = field.unescaped_key().get(key); kError) {
            return reject(RecordRejection::MalformedInput,
                          std::string("malformed member name: ") + simdjson::error_message(kError));
        }
        if (key.size() > kMaximumRecordStringBytes) {
            return reject(RecordRejection::LimitExceeded, "member name exceeds the record string limit");
        }
        std::size_t offset = 0;
        char32_t codePoint = 0;
        while (offset < key.size()) {
            if (!decodeCodePoint(key, offset, codePoint)) {
                return reject(RecordRejection::MalformedInput, "member name contains malformed UTF-8 or a surrogate");
            }
        }
        std::string name(key);
        // Compared after unescaping, so "a" and "a" are one member and the
        // second occurrence is a duplicate rather than a second key.
        const bool kDuplicate = std::ranges::any_of(members, [&name](const CanonicalValue::Member& member) {
            return member.first == name;
        });
        if (kDuplicate) {
            return reject(RecordRejection::MalformedInput, "duplicate decoded member name: " + name);
        }
        if (members.size() >= kMaximumRecordMembers) {
            return reject(RecordRejection::LimitExceeded, "object exceeds the record member limit");
        }
        simdjson::ondemand::value child;
        if (const auto kError = field.value().get(child); kError) {
            return reject(RecordRejection::MalformedInput,
                          std::string("malformed member value: ") + simdjson::error_message(kError));
        }
        auto parsed = parseValue(child, depth + 1);
        if (!parsed) {
            return parsed;
        }
        members.emplace_back(std::move(name), std::move(*parsed));
    }
    return CanonicalValue::makeObject(std::move(members));
}

RecordResult<CanonicalValue> Parser::parseValue(simdjson::ondemand::value value, std::size_t depth) {
    if (depth > kMaximumRecordDepth) {
        return reject(RecordRejection::LimitExceeded, "record nesting exceeds the depth limit");
    }
    if (++nodes > kMaximumRecordNodes) {
        return reject(RecordRejection::LimitExceeded, "record exceeds the node limit");
    }
    simdjson::ondemand::json_type type{};
    if (const auto kError = value.type().get(type); kError) {
        return reject(RecordRejection::MalformedInput,
                      std::string("malformed value: ") + simdjson::error_message(kError));
    }
    switch (type) {
    case simdjson::ondemand::json_type::object: {
        simdjson::ondemand::object object;
        if (const auto kError = value.get_object().get(object); kError) {
            return reject(RecordRejection::MalformedInput, "malformed object");
        }
        return parseObject(object, depth);
    }
    case simdjson::ondemand::json_type::array: {
        simdjson::ondemand::array array;
        if (const auto kError = value.get_array().get(array); kError) {
            return reject(RecordRejection::MalformedInput, "malformed array");
        }
        return parseArray(array, depth);
    }
    case simdjson::ondemand::json_type::number:
        return parseNumber(value);
    case simdjson::ondemand::json_type::string:
        return parseString(value);
    case simdjson::ondemand::json_type::boolean: {
        bool boolean = false;
        if (const auto kError = value.get_bool().get(boolean); kError) {
            return reject(RecordRejection::MalformedInput, "malformed boolean");
        }
        return CanonicalValue::makeBoolean(boolean);
    }
    case simdjson::ondemand::json_type::null:
        return CanonicalValue::makeNull();
    case simdjson::ondemand::json_type::unknown:
        break;
    }
    return reject(RecordRejection::MalformedInput, "value is outside the accepted subset");
}

void appendCanonical(const CanonicalValue& value, std::string& output) {
    switch (value.kind()) {
    case CanonicalValue::Kind::Null:
        output.append("null");
        return;
    case CanonicalValue::Kind::Boolean:
        output.append(value.boolean() ? "true" : "false");
        return;
    case CanonicalValue::Kind::Integer: {
        std::array<char, 24> buffer{};
        const auto kResult = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value.integer());
        output.append(buffer.data(), static_cast<std::size_t>(kResult.ptr - buffer.data()));
        return;
    }
    case CanonicalValue::Kind::String:
        appendEscapedString(value.text(), output);
        return;
    case CanonicalValue::Kind::Array: {
        output.push_back('[');
        bool first = true;
        for (const auto& kElement : value.elements()) {
            if (!first) {
                output.push_back(',');
            }
            first = false;
            appendCanonical(kElement, output);
        }
        output.push_back(']');
        return;
    }
    case CanonicalValue::Kind::Object: {
        output.push_back('{');
        bool first = true;
        for (const auto& kMember : value.members()) {
            if (!first) {
                output.push_back(',');
            }
            first = false;
            appendEscapedString(kMember.first, output);
            output.push_back(':');
            appendCanonical(kMember.second, output);
        }
        output.push_back('}');
        return;
    }
    }
}

} // namespace

CanonicalValue CanonicalValue::makeNull() {
    return {};
}

CanonicalValue CanonicalValue::makeBoolean(bool value) {
    CanonicalValue result;
    result.kind_ = Kind::Boolean;
    result.boolean_ = value;
    return result;
}

CanonicalValue CanonicalValue::makeInteger(std::int64_t value) {
    CanonicalValue result;
    result.kind_ = Kind::Integer;
    result.integer_ = value;
    return result;
}

CanonicalValue CanonicalValue::makeString(std::string value) {
    CanonicalValue result;
    result.kind_ = Kind::String;
    result.text_ = std::move(value);
    return result;
}

CanonicalValue CanonicalValue::makeArray(std::vector<CanonicalValue> elements) {
    CanonicalValue result;
    result.kind_ = Kind::Array;
    result.elements_ = std::move(elements);
    return result;
}

CanonicalValue CanonicalValue::makeObject(std::vector<Member> members) {
    CanonicalValue result;
    result.kind_ = Kind::Object;
    result.members_ = std::move(members);
    std::ranges::sort(result.members_, [](const Member& left, const Member& right) {
        return jcsKeyLess(left.first, right.first);
    });
    return result;
}

const CanonicalValue* CanonicalValue::find(std::string_view name) const noexcept {
    const auto kFound = std::ranges::lower_bound(
        members_,
        name,
        [](std::string_view left, std::string_view right) {
            return jcsKeyLess(left, right);
        },
        &Member::first);
    if (kFound == members_.end() || kFound->first != name) {
        return nullptr;
    }
    return &kFound->second;
}

bool jcsKeyLess(std::string_view left, std::string_view right) {
    std::size_t leftOffset = 0;
    std::size_t rightOffset = 0;
    std::uint32_t leftPending = 0;
    std::uint32_t rightPending = 0;
    while (true) {
        const bool kLeftDone = leftOffset >= left.size() && leftPending == 0;
        const bool kRightDone = rightOffset >= right.size() && rightPending == 0;
        if (kLeftDone || kRightDone) {
            return kLeftDone && !kRightDone;
        }
        std::uint32_t leftUnit = 0;
        std::uint32_t rightUnit = 0;
        if (!nextCodeUnit(left, leftOffset, leftPending, leftUnit) ||
            !nextCodeUnit(right, rightOffset, rightPending, rightUnit)) {
            // Unreachable for keys the parser admitted; ordering stays total
            // rather than undefined if a caller ever hands over raw bytes.
            return left < right;
        }
        if (leftUnit != rightUnit) {
            return leftUnit < rightUnit;
        }
    }
}

RecordResult<CanonicalValue> parseCanonicalSubset(std::string_view bytes) {
    if (bytes.size() > kMaximumRecordBytes) {
        return reject(RecordRejection::LimitExceeded, "record exceeds the byte limit");
    }
    if (bytes.starts_with("\xEF\xBB\xBF")) {
        return reject(RecordRejection::MalformedInput, "record starts with a byte order mark");
    }
    if (bytes.empty()) {
        return reject(RecordRejection::MalformedInput, "record is empty");
    }
    if (bytes.front() != '{') {
        return reject(RecordRejection::MalformedInput, "record does not begin with an object");
    }
    if (bytes.back() != '}') {
        return reject(RecordRejection::MalformedInput, "record does not end with an object");
    }

    simdjson::ondemand::parser parser;
    const simdjson::padded_string kPadded(bytes);
    simdjson::ondemand::document document;
    if (const auto kError = parser.iterate(kPadded).get(document); kError) {
        return reject(RecordRejection::MalformedInput,
                      std::string("record is not JSON: ") + simdjson::error_message(kError));
    }
    simdjson::ondemand::value root;
    if (const auto kError = document.get_value().get(root); kError) {
        return reject(RecordRejection::MalformedInput,
                      std::string("record has no value: ") + simdjson::error_message(kError));
    }
    Parser state;
    auto parsed = state.parseValue(root, 1);
    if (!parsed) {
        return parsed;
    }
    // `at_end` reports that the document was consumed whole, so the rejection
    // is the negation: anything left over is a second record hiding behind the
    // first, and one input carries exactly one record.
    if (!document.at_end()) {
        return reject(RecordRejection::MalformedInput, "record carries trailing content");
    }
    return parsed;
}

std::string serializeCanonical(const CanonicalValue& value) {
    std::string output;
    appendCanonical(value, output);
    return output;
}

RecordResult<CanonicalValue> ingestCanonicalBytes(std::string_view claimed) {
    auto parsed = parseCanonicalSubset(claimed);
    if (!parsed) {
        return parsed;
    }
    const std::string kCanonical = serializeCanonical(*parsed);
    if (kCanonical != claimed) {
        return reject(RecordRejection::NoncanonicalBytes, "submitted bytes are not the canonical form of themselves");
    }
    return parsed;
}

} // namespace rawframe::tool::evidence
