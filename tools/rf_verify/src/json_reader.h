#pragma once

#include "failure.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rawframe::tool::verify {

enum class JsonKind : std::uint8_t {
    Null,
    Boolean,
    Number,
    String,
    Array,
    Object,
};

// A plain document model. Unlike the architecture tool's reader this one does
// not have to preserve the exact bytes of a maintained manifest, because nothing
// it reads is a maintained manifest: a coverage export and a test report are
// generated artifacts whose form is their producer's business.
struct JsonNode {
    JsonKind kind = JsonKind::Null;
    bool boolean = false;
    // The unescaped value for a string, and the literal as written for a number.
    std::string text;
    std::vector<JsonNode> elements;
    std::vector<std::pair<std::string, JsonNode>> members;

    [[nodiscard]] const JsonNode* find(std::string_view key) const noexcept;
    [[nodiscard]] bool isNull() const noexcept {
        return kind == JsonKind::Null;
    }
    [[nodiscard]] bool isBoolean() const noexcept {
        return kind == JsonKind::Boolean;
    }
    [[nodiscard]] bool isNumber() const noexcept {
        return kind == JsonKind::Number;
    }
    [[nodiscard]] bool isString() const noexcept {
        return kind == JsonKind::String;
    }
    [[nodiscard]] bool isArray() const noexcept {
        return kind == JsonKind::Array;
    }
    [[nodiscard]] bool isObject() const noexcept {
        return kind == JsonKind::Object;
    }
};

// Reads and parses one JSON file under the bounded limits. A file that exceeds a
// ceiling is a typed failure, never a partially read document.
[[nodiscard]] Result<JsonNode> readJsonFile(const std::filesystem::path& path);

// Parses bytes already in hand, for fixtures and for tests that construct a
// document without touching the filesystem.
[[nodiscard]] Result<JsonNode> parseJson(std::string_view bytes);

// The integer accessors every consumer here needs. A coverage export states
// counts and line numbers, and a value that is absent, of the wrong kind, or
// outside the representable range is a malformed export rather than a zero.
[[nodiscard]] Result<std::int64_t> readInteger(const JsonNode& node);
[[nodiscard]] Result<std::int64_t> readIntegerAt(const JsonNode& array, std::size_t index);

} // namespace rawframe::tool::verify
