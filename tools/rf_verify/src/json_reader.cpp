#include "json_reader.h"

#include "tool_limits.h"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <ios>
#include <simdjson.h>
#include <string>
#include <system_error>
#include <utility>

namespace rawframe::tool::verify {

namespace {

std::unexpected<Failure> reject(FailureCode code, std::string path, std::string message) {
    return std::unexpected(Failure{code, std::move(path), std::move(message)});
}

// The token view runs to the next structural character, so it carries whatever
// the document put after the number. Only the literal itself is the value, and
// a number literal contains none of these characters, so the first one of them
// ends it. `substr` treats an absent position as the whole string, which is the
// right answer for a token the document did not terminate.
std::string_view trimNumberToken(std::string_view token) {
    return token.substr(0, token.find_first_of(" \t\n\r,}]"));
}

class Builder {
public:
    [[nodiscard]] Result<JsonNode> build(simdjson::ondemand::value value, std::size_t depth);

private:
    [[nodiscard]] Result<JsonNode> buildObject(simdjson::ondemand::object object, std::size_t depth);
    [[nodiscard]] Result<JsonNode> buildArray(simdjson::ondemand::array array, std::size_t depth);

    std::size_t nodes_ = 0;
};

Result<JsonNode> Builder::buildArray(simdjson::ondemand::array array, std::size_t depth) {
    JsonNode node;
    node.kind = JsonKind::Array;
    for (auto element : array) {
        simdjson::ondemand::value child;
        if (const auto kError = element.get(child); kError) {
            return reject(FailureCode::InvalidJson,
                          {},
                          std::string("malformed array element: ") + simdjson::error_message(kError));
        }
        auto built = build(child, depth + 1);
        if (!built) {
            return std::unexpected(built.error());
        }
        node.elements.push_back(std::move(*built));
    }
    return node;
}

Result<JsonNode> Builder::buildObject(simdjson::ondemand::object object, std::size_t depth) {
    JsonNode node;
    node.kind = JsonKind::Object;
    for (auto field : object) {
        std::string_view key;
        if (const auto kError = field.unescaped_key().get(key); kError) {
            return reject(
                FailureCode::InvalidJson, {}, std::string("malformed object key: ") + simdjson::error_message(kError));
        }
        simdjson::ondemand::value child;
        if (const auto kError = field.value().get(child); kError) {
            return reject(FailureCode::InvalidJson,
                          {},
                          std::string("malformed object value: ") + simdjson::error_message(kError));
        }
        auto built = build(child, depth + 1);
        if (!built) {
            return std::unexpected(built.error());
        }
        node.members.emplace_back(std::string(key), std::move(*built));
    }
    return node;
}

Result<JsonNode> Builder::build(simdjson::ondemand::value value, std::size_t depth) {
    if (depth > kMaximumJsonDepth) {
        return reject(FailureCode::LimitExceeded, {}, "document exceeds the nesting limit");
    }
    ++nodes_;
    if (nodes_ > kMaximumJsonNodes) {
        return reject(FailureCode::LimitExceeded, {}, "document exceeds the node limit");
    }

    simdjson::ondemand::json_type type{};
    if (const auto kError = value.type().get(type); kError) {
        return reject(
            FailureCode::InvalidJson, {}, std::string("unreadable value: ") + simdjson::error_message(kError));
    }

    switch (type) {
    case simdjson::ondemand::json_type::object: {
        simdjson::ondemand::object object;
        if (const auto kError = value.get_object().get(object); kError) {
            return reject(FailureCode::InvalidJson, {}, "an object value is not an object");
        }
        return buildObject(object, depth);
    }
    case simdjson::ondemand::json_type::array: {
        simdjson::ondemand::array array;
        if (const auto kError = value.get_array().get(array); kError) {
            return reject(FailureCode::InvalidJson, {}, "an array value is not an array");
        }
        return buildArray(array, depth);
    }
    case simdjson::ondemand::json_type::string: {
        std::string_view text;
        if (const auto kError = value.get_string().get(text); kError) {
            return reject(FailureCode::InvalidJson, {}, "a string value is not a string");
        }
        JsonNode node;
        node.kind = JsonKind::String;
        node.text = std::string(text);
        return node;
    }
    case simdjson::ondemand::json_type::number: {
        const std::string_view kToken = value.raw_json_token();
        JsonNode node;
        node.kind = JsonKind::Number;
        node.text = std::string(trimNumberToken(kToken));
        return node;
    }
    case simdjson::ondemand::json_type::boolean: {
        bool boolean = false;
        if (const auto kError = value.get_bool().get(boolean); kError) {
            return reject(FailureCode::InvalidJson, {}, "a boolean value is not a boolean");
        }
        JsonNode node;
        node.kind = JsonKind::Boolean;
        node.boolean = boolean;
        return node;
    }
    case simdjson::ondemand::json_type::null:
        return JsonNode{};
    case simdjson::ondemand::json_type::unknown:
        break;
    }
    return reject(FailureCode::InvalidJson, {}, "a value of an unknown JSON type");
}

Result<std::string> readFileBytes(const std::filesystem::path& path) {
    // `exists` reports false whenever it sets the error code, so a second test on
    // the error would be an operand that can never decide this on its own.
    std::error_code error;
    if (!std::filesystem::exists(path, error)) {
        return reject(FailureCode::MissingInput, path.generic_string(), "the input file does not exist");
    }
    const auto kSize = std::filesystem::file_size(path, error);
    if (error) {
        return reject(FailureCode::IoFailure, path.generic_string(), "the input file size cannot be read");
    }
    if (kSize > kMaximumJsonBytes) {
        return reject(FailureCode::LimitExceeded, path.generic_string(), "the input file exceeds the byte limit");
    }

    // Read through a stream rather than through simdjson's own loader. The
    // bytes are copied into a `std::string` either way, because `parseJson` pads
    // its own buffer, so the loader bought nothing and pulled a third-party file
    // reader into a path this tool already owns.
    std::ifstream stream(path, std::ios::binary);
    std::string bytes(static_cast<std::size_t>(kSize), '\0');
    stream.read(bytes.data(), static_cast<std::streamsize>(kSize));
    // One question rather than one about opening and another about reading. A
    // path that cannot be opened, a device that fails mid-read, and a file that
    // shrank between the size call and this one all leave the stream failed, and
    // the third is why the short read is a rejection: the bytes measured are no
    // longer the bytes present, and a truncated document is not the document.
    if (!stream) {
        return reject(FailureCode::IoFailure, path.generic_string(), "the input file cannot be read");
    }
    return bytes;
}

} // namespace

const JsonNode* JsonNode::find(std::string_view key) const noexcept {
    for (const auto& member : members) {
        if (member.first == key) {
            return &member.second;
        }
    }
    return nullptr;
}

Result<JsonNode> parseJson(std::string_view bytes) {
    if (bytes.size() > kMaximumJsonBytes) {
        return reject(FailureCode::LimitExceeded, {}, "the document exceeds the byte limit");
    }
    simdjson::ondemand::parser parser;
    simdjson::padded_string padded(bytes);
    simdjson::ondemand::document document;
    if (const auto kError = parser.iterate(padded).get(document); kError) {
        return reject(
            FailureCode::InvalidJson, {}, std::string("the document is not JSON: ") + simdjson::error_message(kError));
    }
    simdjson::ondemand::value root;
    if (const auto kError = document.get_value().get(root); kError) {
        return reject(FailureCode::InvalidJson, {}, "the document has no root value");
    }
    Builder builder;
    return builder.build(root, 0);
}

Result<JsonNode> readJsonFile(const std::filesystem::path& path) {
    auto bytes = readFileBytes(path);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    auto parsed = parseJson(*bytes);
    if (!parsed) {
        Failure failure = parsed.error();
        failure.path = path.generic_string();
        return std::unexpected(failure);
    }
    return parsed;
}

Result<std::int64_t> readInteger(const JsonNode& node) {
    if (!node.isNumber()) {
        return reject(FailureCode::InvalidJson, {}, "a value that must be an integer is not a number");
    }
    std::int64_t value = 0;
    const char* first = node.text.data();
    const char* last = first + node.text.size();
    const auto kParsed = std::from_chars(first, last, value);
    if (kParsed.ec != std::errc{} || kParsed.ptr != last) {
        return reject(FailureCode::InvalidJson, {}, "a value that must be an integer is not one: " + node.text);
    }
    return value;
}

Result<std::int64_t> readIntegerAt(const JsonNode& array, std::size_t index) {
    if (!array.isArray() || index >= array.elements.size()) {
        return reject(FailureCode::InvalidJson, {}, "an expected array position is absent");
    }
    return readInteger(array.elements.at(index));
}

} // namespace rawframe::tool::verify
