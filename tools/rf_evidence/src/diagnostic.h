#pragma once

#include "failure.h"

#include <cstdint>
#include <iosfwd>
#include <string_view>

namespace rawframe::tool::evidence {

enum class OutputFormat : std::uint8_t {
    Human,
    Json,
};

void renderFailure(std::ostream& output, const Failure& failure, OutputFormat format);
void renderSuccess(std::ostream& output, std::string_view operation, std::string_view details, OutputFormat format);
void writeJsonString(std::ostream& output, std::string_view value);

} // namespace rawframe::tool::evidence
