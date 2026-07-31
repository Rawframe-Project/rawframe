#pragma once

#include "failure.h"

#include <cstdint>
#include <filesystem>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::verify {

// A minimal writer for the one JSON shape this tool emits. It exists so that
// reports are byte-identical across hosts: no map ordering, no locale, and no
// floating point, because a report that differs between two runs of the same
// input cannot be compared and therefore cannot be evidence of anything.
class JsonWriter {
public:
    explicit JsonWriter(std::ostream& output) : output_(&output) {
    }

    void beginObject();
    void endObject();
    void beginArray();
    void endArray();
    void key(std::string_view name);
    void writeString(std::string_view value);
    void writeInteger(std::int64_t value);
    void writeBoolean(bool value);
    void writeStringArray(const std::vector<std::string>& values);
    void writeIntegerArray(const std::vector<std::uint32_t>& values);
    void member(std::string_view name, std::string_view value);
    void member(std::string_view name, std::int64_t value);
    void member(std::string_view name, bool value);

private:
    void separate();
    void indent();

    std::ostream* output_;
    std::size_t depth_ = 0;
    bool needsComma_ = false;
    bool afterKey_ = false;
};

// Writes a report to a destination inside the declared write root, creating the
// directories beneath it. A destination outside is refused before anything is
// opened.
[[nodiscard]] Status writeReportFile(const std::filesystem::path& repositoryRoot,
                                     const std::filesystem::path& destination,
                                     std::string_view contents);

} // namespace rawframe::tool::verify
