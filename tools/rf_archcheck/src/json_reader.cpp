#include "json_reader.h"

#include "tool_limits.h"

#include <array>
#include <cstddef>
#include <cstdio>
#include <simdjson.h>
#include <string>
#include <system_error>
#include <utility>

namespace rawframe::tool::archcheck {

namespace {

std::unexpected<Failure> reject(FailureCode code, std::string path, std::string message) {
    return std::unexpected(Failure{code, std::move(path), std::move(message)});
}

class Builder {
public:
    [[nodiscard]] Result<JsonNode> build(simdjson::ondemand::value value, std::size_t depth);

private:
    [[nodiscard]] Result<JsonNode> buildObject(simdjson::ondemand::object object, std::size_t depth);
    [[nodiscard]] Result<JsonNode> buildArray(simdjson::ondemand::array array, std::size_t depth);

    std::size_t nodes_ = 0;
};

// The token view runs to the next structural character, so it carries whatever
// the document put after the number. Only the literal itself is the value.
std::string_view trimNumberToken(std::string_view token) {
    while (!token.empty()) {
        const char kBack = token.back();
        if (kBack == ' ' || kBack == '\t' || kBack == '\n' || kBack == '\r' || kBack == ',' || kBack == '}' ||
            kBack == ']') {
            token.remove_suffix(1);
            continue;
        }
        break;
    }
    return token;
}

Result<JsonNode> Builder::buildArray(simdjson::ondemand::array array, std::size_t depth) {
    JsonNode node;
    node.kind = JsonKind::Array;
    for (auto element : array) {
        if (node.elements.size() >= kMaximumJsonElements) {
            return reject(FailureCode::LimitExceeded, {}, "array exceeds the element limit");
        }
        simdjson::ondemand::value child;
        if (const auto kError = element.get(child); kError) {
            return reject(FailureCode::InvalidJson,
                          {},
                          std::string("malformed array element: ") + simdjson::error_message(kError));
        }
        auto built = build(child, depth + 1);
        if (!built) {
            return built;
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
                FailureCode::InvalidJson, {}, std::string("malformed member name: ") + simdjson::error_message(kError));
        }
        if (key.size() > kMaximumStringLength) {
            return reject(FailureCode::LimitExceeded, {}, "member name exceeds the string limit");
        }
        if (node.members.size() >= kMaximumJsonMembers) {
            return reject(FailureCode::LimitExceeded, {}, "object exceeds the member limit");
        }
        std::string name(key);
        for (const auto& member : node.members) {
            if (member.first == name) {
                return reject(FailureCode::InvalidJson, {}, "duplicate member name: " + name);
            }
        }
        simdjson::ondemand::value child;
        if (const auto kError = field.value().get(child); kError) {
            return reject(FailureCode::InvalidJson,
                          {},
                          std::string("malformed member value: ") + simdjson::error_message(kError));
        }
        auto built = build(child, depth + 1);
        if (!built) {
            return built;
        }
        node.members.emplace_back(std::move(name), std::move(*built));
    }
    return node;
}

Result<JsonNode> Builder::build(simdjson::ondemand::value value, std::size_t depth) {
    if (depth > kMaximumJsonDepth) {
        return reject(FailureCode::LimitExceeded, {}, "document nesting exceeds the depth limit");
    }
    if (++nodes_ > kMaximumJsonElements + kMaximumJsonMembers) {
        return reject(FailureCode::LimitExceeded, {}, "document exceeds the node limit");
    }
    simdjson::ondemand::json_type type{};
    if (const auto kError = value.type().get(type); kError) {
        return reject(FailureCode::InvalidJson, {}, std::string("malformed value: ") + simdjson::error_message(kError));
    }
    JsonNode node;
    switch (type) {
    case simdjson::ondemand::json_type::object: {
        simdjson::ondemand::object object;
        if (const auto kError = value.get_object().get(object); kError) {
            return reject(FailureCode::InvalidJson, {}, "malformed object");
        }
        return buildObject(object, depth);
    }
    case simdjson::ondemand::json_type::array: {
        simdjson::ondemand::array array;
        if (const auto kError = value.get_array().get(array); kError) {
            return reject(FailureCode::InvalidJson, {}, "malformed array");
        }
        return buildArray(array, depth);
    }
    case simdjson::ondemand::json_type::number: {
        node.kind = JsonKind::Number;
        node.text = std::string(trimNumberToken(value.raw_json_token()));
        if (node.text.empty()) {
            return reject(FailureCode::InvalidJson, {}, "empty numeric token");
        }
        return node;
    }
    case simdjson::ondemand::json_type::string: {
        std::string_view text;
        if (const auto kError = value.get_string().get(text); kError) {
            return reject(
                FailureCode::InvalidJson, {}, std::string("malformed string: ") + simdjson::error_message(kError));
        }
        if (text.size() > kMaximumStringLength) {
            return reject(FailureCode::LimitExceeded, {}, "string exceeds the string limit");
        }
        node.kind = JsonKind::String;
        node.text.assign(text);
        return node;
    }
    case simdjson::ondemand::json_type::boolean: {
        bool boolean = false;
        if (const auto kError = value.get_bool().get(boolean); kError) {
            return reject(FailureCode::InvalidJson, {}, "malformed boolean");
        }
        node.kind = JsonKind::Boolean;
        node.boolean = boolean;
        return node;
    }
    case simdjson::ondemand::json_type::null:
        node.kind = JsonKind::Null;
        return node;
    case simdjson::ondemand::json_type::unknown:
        break;
    }
    return reject(FailureCode::InvalidJson, {}, "unsupported JSON value");
}

void appendEscaped(std::string& output, std::string_view text) {
    output.push_back('"');
    for (const char kCharacter : text) {
        const auto kByte = static_cast<unsigned char>(kCharacter);
        switch (kCharacter) {
        case '"':
            output.append("\\\"");
            continue;
        case '\\':
            output.append("\\\\");
            continue;
        case '\b':
            output.append("\\b");
            continue;
        case '\f':
            output.append("\\f");
            continue;
        case '\n':
            output.append("\\n");
            continue;
        case '\r':
            output.append("\\r");
            continue;
        case '\t':
            output.append("\\t");
            continue;
        default:
            break;
        }
        if (kByte < 0x20U) {
            constexpr std::string_view kHexDigits = "0123456789abcdef";
            output.append("\\u00");
            output.push_back(kHexDigits.at((kByte >> 4U) & 0x0FU));
            output.push_back(kHexDigits.at(kByte & 0x0FU));
            continue;
        }
        output.push_back(kCharacter);
    }
    output.push_back('"');
}

void serializeInto(std::string& output, const JsonNode& node, std::size_t indent) {
    const std::string kInner(2 * (indent + 1), ' ');
    const std::string kOuter(2 * indent, ' ');
    switch (node.kind) {
    case JsonKind::Null:
        output.append("null");
        return;
    case JsonKind::Boolean:
        output.append(node.boolean ? "true" : "false");
        return;
    case JsonKind::Number:
        output.append(node.text);
        return;
    case JsonKind::String:
        appendEscaped(output, node.text);
        return;
    case JsonKind::Array:
        if (node.elements.empty()) {
            output.append("[]");
            return;
        }
        output.append("[\n");
        for (std::size_t index = 0; index < node.elements.size(); ++index) {
            output.append(kInner);
            serializeInto(output, node.elements.at(index), indent + 1);
            output.append(index + 1 < node.elements.size() ? ",\n" : "\n");
        }
        output.append(kOuter);
        output.push_back(']');
        return;
    case JsonKind::Object:
        if (node.members.empty()) {
            output.append("{}");
            return;
        }
        output.append("{\n");
        for (std::size_t index = 0; index < node.members.size(); ++index) {
            output.append(kInner);
            appendEscaped(output, node.members.at(index).first);
            output.append(": ");
            serializeInto(output, node.members.at(index).second, indent + 1);
            output.append(index + 1 < node.members.size() ? ",\n" : "\n");
        }
        output.append(kOuter);
        output.push_back('}');
        return;
    }
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
    if (bytes.size() > kMaximumFileBytes) {
        return reject(FailureCode::LimitExceeded, {}, "document exceeds the file byte limit");
    }
    simdjson::padded_string padded(bytes);
    simdjson::ondemand::parser parser;
    simdjson::ondemand::document document;
    if (const auto kError = parser.iterate(padded).get(document); kError) {
        return reject(
            FailureCode::InvalidJson, {}, std::string("document is not JSON: ") + simdjson::error_message(kError));
    }
    simdjson::ondemand::value root;
    if (const auto kError = document.get_value().get(root); kError) {
        return reject(FailureCode::InvalidJson, {}, "document has no root value");
    }
    Builder builder;
    return builder.build(root, 0);
}

Result<JsonDocument> readJsonDocument(const std::filesystem::path& path) {
    std::error_code code;
    const auto kStatus = std::filesystem::symlink_status(path, code);
    if (code) {
        return reject(FailureCode::IoFailure, path.generic_string(), "cannot stat the file");
    }
    if (std::filesystem::is_symlink(kStatus)) {
        return reject(FailureCode::InvalidPath, path.generic_string(), "the path is a link");
    }
    if (!std::filesystem::is_regular_file(kStatus)) {
        return reject(FailureCode::MissingInput, path.generic_string(), "the path is not an ordinary file");
    }
    const auto kSize = std::filesystem::file_size(path, code);
    if (code) {
        return reject(FailureCode::IoFailure, path.generic_string(), "cannot size the file");
    }
    if (kSize > kMaximumFileBytes) {
        return reject(FailureCode::LimitExceeded, path.generic_string(), "the file exceeds the byte limit");
    }

    JsonDocument document;
    {
        std::FILE* handle = nullptr;
#ifdef _WIN32
        if (::_wfopen_s(&handle, path.c_str(), L"rb") != 0 || handle == nullptr) {
            return reject(FailureCode::IoFailure, path.generic_string(), "cannot open the file");
        }
#else
        handle = std::fopen(path.c_str(), "rb");
        if (handle == nullptr) {
            return reject(FailureCode::IoFailure, path.generic_string(), "cannot open the file");
        }
#endif
        std::string raw;
        raw.resize(static_cast<std::size_t>(kSize));
        const std::size_t kRead = std::fread(raw.data(), 1, raw.size(), handle);
        const bool kFailed = std::ferror(handle) != 0;
        (void)std::fclose(handle);
        if (kFailed || kRead != raw.size()) {
            return reject(FailureCode::IoFailure, path.generic_string(), "cannot read the file");
        }
        document.bytes.reserve(raw.size());
        for (std::size_t index = 0; index < raw.size(); ++index) {
            if (raw.at(index) == '\r' && index + 1 < raw.size() && raw.at(index + 1) == '\n') {
                continue;
            }
            document.bytes.push_back(raw.at(index));
        }
    }

    auto parsed = parseJson(document.bytes);
    if (!parsed) {
        auto failure = parsed.error();
        failure.path = path.generic_string();
        return std::unexpected(failure);
    }
    document.root = std::move(*parsed);
    return document;
}

std::string serializeMaintainedForm(const JsonNode& node) {
    std::string output;
    serializeInto(output, node, 0);
    return output;
}

} // namespace rawframe::tool::archcheck
