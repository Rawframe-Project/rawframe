#include "text_scan.h"

#include <array>
#include <cctype>

namespace rawframe::tool::archcheck {

namespace {

struct Line {
    std::string_view text;
    std::size_t number = 0;
};

std::vector<Line> splitLines(std::string_view text) {
    std::vector<Line> lines;
    std::size_t offset = 0;
    std::size_t number = 1;
    while (offset <= text.size()) {
        const auto kEnd = text.find('\n', offset);
        const auto kStop = kEnd == std::string_view::npos ? text.size() : kEnd;
        lines.push_back(Line{text.substr(offset, kStop - offset), number});
        if (kEnd == std::string_view::npos) {
            break;
        }
        offset = kEnd + 1;
        ++number;
    }
    return lines;
}

// Everything from an unquoted `#` to the end of the line. Both CMake and C++
// treat a `#` inside a string as text, so the quote state has to be tracked or
// a path containing one would hide the rest of the line.
std::string_view stripComment(std::string_view line, char commentCharacter) {
    bool quoted = false;
    for (std::size_t index = 0; index < line.size(); ++index) {
        const char kCharacter = line.at(index);
        if (kCharacter == '\\' && quoted) {
            ++index;
            continue;
        }
        if (kCharacter == '"') {
            quoted = !quoted;
            continue;
        }
        if (kCharacter == commentCharacter && !quoted) {
            return line.substr(0, index);
        }
    }
    return line;
}

bool isIdentifierCharacter(char character) {
    const auto kByte = static_cast<unsigned char>(character);
    return std::isalnum(kByte) != 0 || character == '_';
}

} // namespace

std::vector<TextMatch> findCommandInvocations(std::string_view text, std::string_view command) {
    std::vector<TextMatch> matches;
    for (const auto& line : splitLines(text)) {
        const std::string_view kCode = stripComment(line.text, '#');
        std::size_t offset = 0;
        while (offset < kCode.size()) {
            const auto kFound = kCode.find(command, offset);
            if (kFound == std::string_view::npos) {
                break;
            }
            offset = kFound + 1;
            if (kFound > 0 && isIdentifierCharacter(kCode.at(kFound - 1))) {
                continue;
            }
            std::size_t after = kFound + command.size();
            while (after < kCode.size() && (kCode.at(after) == ' ' || kCode.at(after) == '\t')) {
                ++after;
            }
            if (after >= kCode.size() || kCode.at(after) != '(') {
                continue;
            }
            matches.push_back(TextMatch{Position{line.number, kFound + 1}, std::string(command)});
        }
    }
    return matches;
}

std::vector<TextMatch> findLiteral(std::string_view text, std::string_view needle) {
    std::vector<TextMatch> matches;
    if (needle.empty()) {
        return matches;
    }
    for (const auto& line : splitLines(text)) {
        const std::string_view kCode = stripComment(line.text, '#');
        std::size_t offset = 0;
        while (offset < kCode.size()) {
            const auto kFound = kCode.find(needle, offset);
            if (kFound == std::string_view::npos) {
                break;
            }
            matches.push_back(TextMatch{Position{line.number, kFound + 1}, std::string(needle)});
            offset = kFound + needle.size();
        }
    }
    return matches;
}

std::string_view lineAt(std::string_view text, std::size_t number) {
    for (const auto& line : splitLines(text)) {
        if (line.number == number) {
            return line.text;
        }
    }
    return {};
}

std::vector<IncludeDirective> findIncludes(std::string_view text) {
    std::vector<IncludeDirective> includes;
    for (const auto& line : splitLines(text)) {
        std::string_view code = line.text;
        std::size_t start = 0;
        while (start < code.size() && (code.at(start) == ' ' || code.at(start) == '\t')) {
            ++start;
        }
        code = code.substr(start);
        if (!code.starts_with("#include")) {
            continue;
        }
        std::size_t offset = std::string_view{"#include"}.size();
        while (offset < code.size() && (code.at(offset) == ' ' || code.at(offset) == '\t')) {
            ++offset;
        }
        if (offset >= code.size()) {
            continue;
        }
        const char kOpen = code.at(offset);
        char closing = '\0';
        if (kOpen == '<') {
            closing = '>';
        } else if (kOpen == '"') {
            closing = '"';
        } else {
            continue;
        }
        const char kClose = closing;
        const auto kEnd = code.find(kClose, offset + 1);
        if (kEnd == std::string_view::npos) {
            continue;
        }
        IncludeDirective directive;
        directive.position = Position{line.number, start + offset + 2};
        directive.target = std::string(code.substr(offset + 1, kEnd - offset - 1));
        directive.angled = kOpen == '<';
        includes.push_back(std::move(directive));
    }
    return includes;
}

bool declaresItselfGenerated(std::string_view text, Position& position) {
    constexpr std::array kMarkers{
        std::string_view{"@generated"},
        std::string_view{"DO NOT EDIT"},
        std::string_view{"do not edit"},
        std::string_view{"Generated by"},
        std::string_view{"AUTOGENERATED"},
    };
    std::size_t inspected = 0;
    for (const auto& line : splitLines(text)) {
        if (++inspected > 20) {
            break;
        }
        for (const std::string_view kMarker : kMarkers) {
            const auto kFound = line.text.find(kMarker);
            if (kFound == std::string_view::npos) {
                continue;
            }
            position = Position{line.number, kFound + 1};
            return true;
        }
    }
    return false;
}

} // namespace rawframe::tool::archcheck
