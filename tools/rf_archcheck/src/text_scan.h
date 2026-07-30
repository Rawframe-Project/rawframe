#pragma once

#include "findings.h"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::archcheck {

struct TextMatch {
    Position position;
    std::string matched;
};

// A build file is read lexically, not evaluated. That is deliberate: evaluating
// it would mean running it, and a check that has to run the thing it judges can
// be defeated by the thing it judges. Comments are skipped because a rule about
// what a build file does has nothing to say about what it describes.
[[nodiscard]] std::vector<TextMatch> findCommandInvocations(std::string_view text, std::string_view command);

// Every occurrence of a literal outside a comment.
[[nodiscard]] std::vector<TextMatch> findLiteral(std::string_view text, std::string_view needle);

// The one-based line, empty when the text has no such line.
[[nodiscard]] std::string_view lineAt(std::string_view text, std::size_t number);

// The `#include <...>` and `#include "..."` targets of one translation unit,
// with the position of each. ADR-0008's dialect has no conditional inclusion in
// first-party source, so a lexical pass and a preprocessor see the same set.
struct IncludeDirective {
    Position position;
    std::string target;
    bool angled = false;
};

[[nodiscard]] std::vector<IncludeDirective> findIncludes(std::string_view text);

// The first line of a file that declares the file generated, if any. The marker
// set is the one generators actually write, and a file that says it is generated
// is taken at its word.
[[nodiscard]] bool declaresItselfGenerated(std::string_view text, Position& position);

} // namespace rawframe::tool::archcheck
