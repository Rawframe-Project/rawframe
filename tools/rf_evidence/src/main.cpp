#include "command.h"

#include <iostream>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

int main(int argumentCount, char** argumentValues) {
#ifdef _WIN32
    // `get blob` returns exact stored bytes, and text-mode standard output
    // rewrites 0x0A as 0x0D 0x0A on Windows, which would make the process
    // hand back content the store never held. Canonical records happen to
    // carry no raw control byte, so no existing operation changes; this is set
    // once, here, rather than left as a property of what the bytes happen to be.
    static_cast<void>(_setmode(_fileno(stdout), _O_BINARY));
#endif
    std::vector<std::string_view> arguments;
    arguments.reserve(argumentCount > 1 ? static_cast<std::size_t>(argumentCount - 1) : 0U);
    for (int index = 1; index < argumentCount; ++index) {
        arguments.emplace_back(argumentValues[index]);
    }
    return rawframe::tool::evidence::runCommand(arguments, std::cout, std::cerr);
}
