#include "command.h"

#include <iostream>
#include <string_view>
#include <vector>

int main(int argumentCount, char** argumentValues) {
    std::vector<std::string_view> arguments;
    arguments.reserve(argumentCount > 1 ? static_cast<std::size_t>(argumentCount - 1) : 0U);
    for (int index = 1; index < argumentCount; ++index) {
        arguments.emplace_back(argumentValues[index]);
    }
    return rawframe::tool::evidence::runCommand(arguments, std::cout, std::cerr);
}
