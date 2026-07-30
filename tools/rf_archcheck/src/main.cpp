#include "command.h"

#include <cstdio>
#include <span>
#include <string_view>
#include <vector>

// The one diagnostic boundary. Everything below returns values; this is where
// they become bytes and an exit status, once, per ADR-0009.
int main(int argc, char** argv) {
    std::vector<std::string_view> arguments;
    arguments.reserve(argc > 1 ? static_cast<std::size_t>(argc - 1) : 0);
    for (int index = 1; index < argc; ++index) {
        arguments.emplace_back(argv[index]);
    }
    const rawframe::tool::archcheck::CommandOutput kOutput =
        rawframe::tool::archcheck::runCommand(std::span<const std::string_view>(arguments));
    if (!kOutput.standardOutput.empty()) {
        (void)std::fwrite(kOutput.standardOutput.data(), 1, kOutput.standardOutput.size(), stdout);
    }
    if (!kOutput.standardError.empty()) {
        (void)std::fwrite(kOutput.standardError.data(), 1, kOutput.standardError.size(), stderr);
    }
    return static_cast<int>(kOutput.exitClass);
}
