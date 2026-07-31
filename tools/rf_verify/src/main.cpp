#include "command.h"

#include <iostream>
#include <span>
#include <string_view>
#include <vector>

int main(int argc, char** argv) {
    std::vector<std::string_view> arguments;
    // `argc` is never negative, so the cast is total and the reserve needs no
    // guard. Over-reserving by one when the program name is present costs a
    // pointer and avoids a branch no invocation can take.
    arguments.reserve(static_cast<std::size_t>(argc));
    for (int index = 1; index < argc; ++index) {
        arguments.emplace_back(argv[index]);
    }
    return rawframe::tool::verify::runCommand(std::span<const std::string_view>(arguments), std::cout, std::cerr);
}
