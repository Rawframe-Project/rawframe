#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace rawframe::tool::archcheck {

// SPEC-0044's four typed exit classes. The distinction that matters is between
// Findings and InternalError: one is a statement about the repository and the
// other is a statement about the tool.
enum class ExitClass : std::uint8_t {
    Clean = 0,
    Findings = 1,
    UsageError = 2,
    InternalError = 3,
};

struct CommandOutput {
    ExitClass exitClass = ExitClass::Clean;
    // Everything the invocation has to say, emitted once at the boundary. A
    // check never logs; it returns a finding or it does not.
    std::string standardOutput;
    std::string standardError;
};

[[nodiscard]] CommandOutput runCommand(std::span<const std::string_view> arguments);

} // namespace rawframe::tool::archcheck
