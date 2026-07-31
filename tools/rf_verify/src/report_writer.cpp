#include "report_writer.h"

#include "repository_paths.h"

#include <fstream>
#include <ios>
#include <ostream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace rawframe::tool::verify {

namespace {

std::unexpected<Failure> reject(FailureCode code, std::string path, std::string message) {
    return std::unexpected(Failure{code, std::move(path), std::move(message)});
}

void appendEscaped(std::ostream& output, std::string_view value) {
    output << '"';
    for (const char kCharacter : value) {
        switch (kCharacter) {
        case '"':
            output << "\\\"";
            break;
        case '\\':
            output << "\\\\";
            break;
        case '\n':
            output << "\\n";
            break;
        case '\r':
            output << "\\r";
            break;
        case '\t':
            output << "\\t";
            break;
        default:
            if (static_cast<unsigned char>(kCharacter) < 0x20) {
                // Everything that reaches here is below 0x20, so the leading hex
                // pair is always zero and two digits always suffice.
                constexpr std::string_view kDigits = "0123456789abcdef";
                const auto kByte = static_cast<unsigned char>(kCharacter);
                output << "\\u00" << kDigits.at(kByte >> 4U) << kDigits.at(kByte & 0x0FU);
                break;
            }
            output << kCharacter;
            break;
        }
    }
    output << '"';
}

} // namespace

void JsonWriter::separate() {
    if (afterKey_) {
        afterKey_ = false;
        return;
    }
    if (needsComma_) {
        *output_ << ",\n";
    } else if (depth_ > 0) {
        *output_ << "\n";
    }
    indent();
}

void JsonWriter::indent() {
    for (std::size_t level = 0; level < depth_; ++level) {
        *output_ << "  ";
    }
}

void JsonWriter::beginObject() {
    separate();
    *output_ << '{';
    ++depth_;
    needsComma_ = false;
}

void JsonWriter::endObject() {
    --depth_;
    if (needsComma_) {
        *output_ << '\n';
        indent();
    }
    *output_ << '}';
    needsComma_ = true;
}

void JsonWriter::beginArray() {
    separate();
    *output_ << '[';
    ++depth_;
    needsComma_ = false;
}

void JsonWriter::endArray() {
    --depth_;
    if (needsComma_) {
        *output_ << '\n';
        indent();
    }
    *output_ << ']';
    needsComma_ = true;
}

void JsonWriter::key(std::string_view name) {
    separate();
    appendEscaped(*output_, name);
    *output_ << ": ";
    afterKey_ = true;
    needsComma_ = false;
}

void JsonWriter::writeString(std::string_view value) {
    separate();
    appendEscaped(*output_, value);
    needsComma_ = true;
}

void JsonWriter::writeInteger(std::int64_t value) {
    separate();
    *output_ << value;
    needsComma_ = true;
}

void JsonWriter::writeBoolean(bool value) {
    separate();
    *output_ << (value ? "true" : "false");
    needsComma_ = true;
}

void JsonWriter::writeStringArray(const std::vector<std::string>& values) {
    beginArray();
    for (const auto& value : values) {
        writeString(value);
    }
    endArray();
}

void JsonWriter::writeIntegerArray(const std::vector<std::uint32_t>& values) {
    beginArray();
    for (const auto kValue : values) {
        writeInteger(static_cast<std::int64_t>(kValue));
    }
    endArray();
}

void JsonWriter::member(std::string_view name, std::string_view value) {
    key(name);
    writeString(value);
}

void JsonWriter::member(std::string_view name, std::int64_t value) {
    key(name);
    writeInteger(value);
}

void JsonWriter::member(std::string_view name, bool value) {
    key(name);
    writeBoolean(value);
}

Status writeReportFile(const std::filesystem::path& repositoryRoot,
                       const std::filesystem::path& destination,
                       std::string_view contents) {
    if (auto status = ensureWithinReportRoot(repositoryRoot, destination); !status) {
        return status;
    }

    const auto kAbsolute = destination.is_absolute() ? destination : repositoryRoot / destination;
    std::error_code error;
    std::filesystem::create_directories(kAbsolute.parent_path(), error);
    if (error) {
        return reject(FailureCode::IoFailure, destination.generic_string(), "the report directory cannot be created");
    }

    std::ofstream output(kAbsolute, std::ios::binary | std::ios::trunc);
    if (!output) {
        return reject(FailureCode::IoFailure, destination.generic_string(), "the report cannot be opened for writing");
    }
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    output.flush();
    if (!output) {
        return reject(FailureCode::IoFailure, destination.generic_string(), "the report cannot be written");
    }
    return {};
}

} // namespace rawframe::tool::verify
