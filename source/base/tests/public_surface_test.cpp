// SPEC-0046 conformance items 4 and 5.
//
// Item 4 asks that base's public surface enumerate to exactly what SPEC-0046
// declares, and that a symbol present and unspecified fail. That has to be
// mechanical or it is a review opinion, and the mechanism has to read the headers
// themselves, because the headers are the surface: almost everything base
// publishes is a type, an alias, a macro, or a constexpr function, and none of
// those leave a symbol in the static library to enumerate.
//
// The scan leans on one rule STD-0002 already enforces and SPEC-0046 restates:
// every published declaration carries a `///` comment. A `///` run at namespace
// scope therefore introduces exactly one published declaration, and macros are
// collected separately because a macro can be defined once per preprocessor
// branch and the `///` sits on only one of them.
//
// Anything the extractor cannot classify fails the test rather than being
// skipped. An unrecognised declaration is by definition an unspecified one, and
// skipping it would invert the item it exists to prove.

#include <algorithm>
#include <cctype>
#include <fstream>
#include <gtest/gtest.h>
#include <ios>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

std::string readMaintainedFile(std::string_view relativePath) {
    std::string path{RAWFRAME_BASE_SOURCE_ROOT};
    path += '/';
    path.append(relativePath);
    std::ifstream stream(path, std::ios::binary);
    std::ostringstream contents;
    contents << stream.rdbuf();
    EXPECT_FALSE(stream.bad()) << "unreadable maintained file: " << path;
    return contents.str();
}

std::vector<std::string> splitLines(const std::string& text) {
    std::vector<std::string> lines;
    std::string current;
    for (const char kCharacter : text) {
        if (kCharacter == '\n') {
            if (!current.empty() && current.back() == '\r') {
                current.pop_back();
            }
            lines.push_back(current);
            current.clear();
            continue;
        }
        current.push_back(kCharacter);
    }
    if (!current.empty()) {
        lines.push_back(current);
    }
    return lines;
}

std::string_view trim(std::string_view text) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
    }
    return text;
}

/// Indexing spelled as pointer arithmetic. The bounds-safe alternative the
/// analyzer asks for is `at`, which throws, and ADR-0008 disables exceptions;
/// the repository's analysis policy admits pointer arithmetic for exactly this
/// reason. Every call below is bounded by the loop condition above it.
char characterAt(std::string_view text, std::size_t index) {
    return *(text.data() + index);
}

bool isIdentifierCharacter(char character) {
    return std::isalnum(static_cast<unsigned char>(character)) != 0 || character == '_';
}

/// The net brace depth a line leaves behind, with `namespace` treated as
/// transparent so that a declaration directly inside `namespace rawframe::base`
/// counts as top level and a struct member does not.
int braceDelta(std::string_view line) {
    const std::string_view kText = trim(line);
    if (kText.starts_with("namespace ") || kText.starts_with("namespace{") || kText.starts_with("} // namespace")) {
        return 0;
    }
    int delta = 0;
    bool inString = false;
    for (std::size_t index = 0; index < line.size(); ++index) {
        const char kCharacter = characterAt(line, index);
        if (kCharacter == '"' && (index == 0 || characterAt(line, index - 1) != '\\')) {
            inString = !inString;
        }
        if (inString) {
            continue;
        }
        if (kCharacter == '{') {
            ++delta;
        } else if (kCharacter == '}') {
            --delta;
        }
    }
    return delta;
}

/// One declaration found at namespace scope: the joined text and whether a `///`
/// run introduced it.
struct TopLevelDeclaration {
    std::string text;
    bool documented = false;
};

/// Every namespace-scope declaration in a maintained file, with preprocessor
/// lines and comments removed and wrapped declarations joined. A declaration ends
/// at the first semicolon or opening brace, which covers the aliases, functions,
/// objects, and types base actually declares.
std::vector<TopLevelDeclaration> scanTopLevelDeclarations(std::string_view relativePath,
                                                          std::vector<std::string>& macrosOut) {
    const std::vector<std::string> kLines = splitLines(readMaintainedFile(relativePath));
    std::vector<TopLevelDeclaration> declarations;
    int depth = 0;
    bool documented = false;
    bool continuingMacro = false;

    for (std::size_t index = 0; index < kLines.size(); ++index) {
        const std::string& raw = *(kLines.data() + index);
        // A multi-line macro body is one preprocessor line. Reading its lines as
        // source would report `do {` as a published declaration and would count
        // the braces of a body that never reaches the compiler as written.
        const bool kWasContinuing = continuingMacro;
        continuingMacro = !raw.empty() && raw.back() == '\\';
        if (kWasContinuing) {
            continue;
        }

        const std::string_view kLine = trim(raw);
        if (kLine.starts_with("#")) {
            if (kLine.starts_with("#define ")) {
                std::string_view name = kLine.substr(8);
                std::size_t stop = 0;
                while (stop < name.size() && isIdentifierCharacter(characterAt(name, stop))) {
                    ++stop;
                }
                macrosOut.emplace_back(name.substr(0, stop));
                // The macro consumed the comment run. Without this a documented
                // macro would lend its documentation to the next declaration a
                // preprocessor branch happens to put after it.
                documented = false;
            }
            continue;
        }

        const int kEnteringDepth = depth;
        depth += braceDelta(raw);

        if (kLine.starts_with("///")) {
            if (kEnteringDepth == 0) {
                documented = true;
            }
            continue;
        }
        if (kLine.empty() || kLine.starts_with("//")) {
            continue;
        }
        // A namespace is a scope, not a declaration this scan reports on, and
        // `braceDelta` already treats it as transparent.
        if (kLine.starts_with("namespace") || kLine.starts_with("}")) {
            continue;
        }
        if (kEnteringDepth != 0) {
            continue;
        }

        std::string joined{kLine};
        std::size_t cursor = index;
        while (!joined.contains(';') && !joined.contains('{') && cursor + 1 < kLines.size()) {
            ++cursor;
            joined += ' ';
            const std::string& kContinued = *(kLines.data() + cursor);
            joined.append(trim(kContinued));
            depth += braceDelta(kContinued);
        }
        declarations.push_back(TopLevelDeclaration{joined, documented});
        documented = false;
        // A line already consumed into a wrapped declaration is not a second
        // declaration. Reading it again reported the tail of a wrapped
        // `static_assert` as a namespace-scope object of its own.
        index = cursor;
    }

    EXPECT_EQ(depth, 0) << relativePath << " does not close every brace it opens";
    return declarations;
}

std::string identifierAfter(std::string_view text, std::string_view keyword) {
    const std::size_t kStart = text.find(keyword);
    if (kStart == std::string_view::npos) {
        return {};
    }
    std::size_t cursor = kStart + keyword.size();
    while (cursor < text.size() && !isIdentifierCharacter(characterAt(text, cursor))) {
        ++cursor;
    }
    const std::size_t kBegin = cursor;
    while (cursor < text.size() && isIdentifierCharacter(characterAt(text, cursor))) {
        ++cursor;
    }
    return std::string{text.substr(kBegin, cursor - kBegin)};
}

/// The identifier a function or object declaration declares: the one immediately
/// before the parameter list, or before the initializer when there is none.
std::string declaredEntityName(std::string_view text) {
    std::size_t boundary = text.find('(');
    if (boundary == std::string_view::npos) {
        boundary = text.find('=');
    }
    if (boundary == std::string_view::npos) {
        boundary = text.find(';');
    }
    if (boundary == std::string_view::npos) {
        return {};
    }
    std::size_t cursor = boundary;
    while (cursor > 0 && !isIdentifierCharacter(characterAt(text, cursor - 1))) {
        --cursor;
    }
    const std::size_t kEnd = cursor;
    while (cursor > 0 && isIdentifierCharacter(characterAt(text, cursor - 1))) {
        --cursor;
    }
    return std::string{text.substr(cursor, kEnd - cursor)};
}

/// One published declaration's name, or an empty string when the extractor does
/// not recognise the shape. An empty result is a test failure at the call site.
std::string publishedName(std::string_view declaration) {
    const std::string_view kText = trim(declaration);
    if (kText.starts_with("enum class ")) {
        return identifierAfter(kText, "enum class ");
    }
    if (kText.starts_with("struct ")) {
        return identifierAfter(kText, "struct ");
    }
    if (kText.starts_with("using ")) {
        return identifierAfter(kText, "using ");
    }
    if (kText.starts_with("template <> struct ")) {
        const std::size_t kStart = kText.find("struct ") + std::string_view{"struct "}.size();
        const std::size_t kStop = kText.find('{', kStart);
        if (kStop == std::string_view::npos) {
            return {};
        }
        return std::string{trim(kText.substr(kStart, kStop - kStart))};
    }
    return declaredEntityName(kText);
}

std::vector<std::string> sortedUnique(std::vector<std::string> values) {
    std::ranges::sort(values);
    const auto kDuplicates = std::ranges::unique(values);
    values.erase(kDuplicates.begin(), kDuplicates.end());
    return values;
}

/// Every name a public header publishes, sorted and deduplicated. Order is not
/// asserted: the signatures are held by the tests that call them, and asserting
/// declaration order here would add fragility without adding safety.
std::vector<std::string> scanPublishedNames(std::string_view relativePath) {
    std::vector<std::string> names;
    for (const TopLevelDeclaration& declaration : scanTopLevelDeclarations(relativePath, names)) {
        if (!declaration.documented) {
            continue;
        }
        const std::string kName = publishedName(declaration.text);
        EXPECT_FALSE(kName.empty()) << relativePath << " publishes a declaration this scan does not recognise, "
                                    << "which makes it an unspecified symbol: " << declaration.text;
        if (!kName.empty()) {
            names.push_back(kName);
        }
    }
    return sortedUnique(std::move(names));
}

} // namespace

// Item 4. The inventory is SPEC-0046's, transcribed once. A declaration added to
// a header without a matching entry here fails, and an entry here with no
// declaration fails too, so the list cannot rot in either direction.
TEST(PublicSurface, EnumeratesToExactlyWhatTheSpecificationDeclares) {
    RecordProperty("requirement", "SPEC-0046:item-4-public-surface-enumerates-exactly");

    const std::vector<std::pair<std::string_view, std::vector<std::string>>> kExpected{
        {"include/rawframe/base/platform.h",
         {"RAWFRAME_ARCH_X86_64", "RAWFRAME_COMPILER_CLANG", "RAWFRAME_COMPILER_MSVC", "RAWFRAME_DEBUG_BREAK"}},
        {"include/rawframe/base/fatal.h",
         {"FatalHandler",
          "FatalReason",
          "FatalRecord",
          "freezeFatalHandler",
          "installFatalHandler",
          "kMaximumFatalTextBytes",
          "raiseFatal"}},
        {"include/rawframe/base/assert.h", {"RAWFRAME_ASSERT", "RAWFRAME_CHECK", "RAWFRAME_PANIC"}},
        {"include/rawframe/base/bits128.h",
         {"Bits128",
          "Bits128Parse",
          "formatBits128Hex",
          "kBits128HexDigits",
          "parseBits128Hex",
          "std::hash<rawframe::base::Bits128>"}},
        {"include/rawframe/base/bytes.h", {"ByteSpan", "MutableByteSpan"}},
    };

    for (const auto& [header, declarations] : kExpected) {
        EXPECT_EQ(scanPublishedNames(header), declarations) << "the published surface of " << header << " changed";
    }
}

// Item 5. Two process-global mutable objects, both in the fatal implementation,
// both `constinit`. The count is asserted and so is the absence of a third,
// because "exactly two" is the half a count alone would not hold.
TEST(PublicSurface, OwnsExactlyTwoConstinitProcessGlobals) {
    RecordProperty("requirement", "SPEC-0046:item-5-exactly-two-constinit-globals");

    std::vector<std::string> macros;
    int constinitObjects = 0;
    std::vector<std::string> otherObjects;

    for (const TopLevelDeclaration& declaration : scanTopLevelDeclarations("src/fatal.cpp", macros)) {
        const std::string_view kText = declaration.text;
        // A function, a type, an alias, and a compile-time assertion are not
        // objects. What survives at namespace scope is an object definition.
        if (kText.starts_with("static_assert") || kText.starts_with("using ") || kText.starts_with("struct ") ||
            kText.starts_with("enum ") || kText.contains('(')) {
            continue;
        }
        if (kText.contains("constinit")) {
            ++constinitObjects;
            continue;
        }
        if (kText.contains("constexpr")) {
            continue;
        }
        otherObjects.emplace_back(kText);
    }

    EXPECT_EQ(constinitObjects, 2) << "base owns exactly two process-global mutable objects";
    EXPECT_TRUE(otherObjects.empty()) << "a namespace-scope object that is neither constexpr nor constinit: "
                                      << (otherObjects.empty() ? std::string{} : otherObjects.front());
}
