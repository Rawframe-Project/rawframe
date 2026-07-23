#pragma once

#include "failure.h"

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace rawframe::tool::evidence {

struct ProcessRequest {
    std::filesystem::path executable;
    std::vector<std::string> arguments;
    std::filesystem::path workingDirectory;
    std::filesystem::path captureDirectory;
    std::chrono::milliseconds timeout{15'000};
    std::size_t maximumStandardOutputBytes{1'048'576};
    std::size_t maximumStandardErrorBytes{1'048'576};
    std::size_t maximumPrivateMemoryBytes{268'435'456};
};

struct ProcessResult {
    int exitCode;
    std::string standardOutput;
    std::string standardError;
};

[[nodiscard]] Result<ProcessResult> runBoundedProcess(const ProcessRequest& request);

} // namespace rawframe::tool::evidence
