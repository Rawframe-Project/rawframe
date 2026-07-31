#pragma once

#include <ostream>
#include <span>
#include <string_view>

namespace rawframe::tool::verify {

// The exit codes SPEC-0044 fixes for a repository conformance tool, applied
// here without reinterpretation: a conformant subject and a subject with
// findings are both successful runs of the tool, and only the last two mean the
// tool could not answer.
inline constexpr int kExitConformant = 0;
inline constexpr int kExitFindings = 1;
inline constexpr int kExitUsage = 2;
inline constexpr int kExitToolFailure = 3;

[[nodiscard]] int runCommand(std::span<const std::string_view> arguments, std::ostream& output, std::ostream& errors);

} // namespace rawframe::tool::verify
