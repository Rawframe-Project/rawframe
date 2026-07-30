#pragma once

#include "failure.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rawframe::tool::archcheck {

enum class JsonKind : std::uint8_t {
    Null,
    Boolean,
    Number,
    String,
    Array,
    Object,
};

// A document model that keeps what a JSON library normally throws away: member
// order and the exact text of every number. Both are required, because SPEC-0001
// makes the maintained form of a manifest part of its identity, and a model that
// sorted its keys or reformatted its numbers could not tell a normalized
// manifest from an unnormalized one.
struct JsonNode {
    JsonKind kind = JsonKind::Null;
    bool boolean = false;
    // The unescaped value for a string, and the literal as written for a number.
    std::string text;
    std::vector<JsonNode> elements;
    std::vector<std::pair<std::string, JsonNode>> members;

    [[nodiscard]] const JsonNode* find(std::string_view key) const noexcept;
    [[nodiscard]] bool isObject() const noexcept {
        return kind == JsonKind::Object;
    }
    [[nodiscard]] bool isArray() const noexcept {
        return kind == JsonKind::Array;
    }
    [[nodiscard]] bool isString() const noexcept {
        return kind == JsonKind::String;
    }
};

struct JsonDocument {
    // The stored bytes with CRLF collapsed to LF. Line endings are the working
    // tree's business and `.gitattributes` owns them; every check here is about
    // structure, so normalizing first keeps a Windows checkout from failing a
    // rule that has nothing to say about it.
    std::string bytes;
    JsonNode root;
};

// Reads and parses one JSON file under the bounded limits. A file that exceeds
// a ceiling is a typed failure, never a partially read document.
[[nodiscard]] Result<JsonDocument> readJsonDocument(const std::filesystem::path& path);

// Parses bytes already in hand, for fixtures and for tests that construct a
// document without touching the filesystem.
[[nodiscard]] Result<JsonNode> parseJson(std::string_view bytes);

// Re-serializes a node in the SPEC-0001 maintained form: two-space indentation,
// one member or element per line, a space after every key colon, and no trailing
// whitespace. The caller adds the single final newline.
[[nodiscard]] std::string serializeMaintainedForm(const JsonNode& node);

} // namespace rawframe::tool::archcheck
