#include "diagnostic.h"

#include <ostream>

namespace rawframe::tool::evidence {

void writeJsonString(std::ostream& output, std::string_view value) {
    output << '"';
    for (const unsigned char kCharacter : value) {
        switch (kCharacter) {
        case '"':
            output << "\\\"";
            break;
        case '\\':
            output << "\\\\";
            break;
        case '\b':
            output << "\\b";
            break;
        case '\f':
            output << "\\f";
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
            if (kCharacter < 0x20U) {
                constexpr std::string_view kHex = "0123456789abcdef";
                output << "\\u00" << kHex.at(kCharacter >> 4U) << kHex.at(kCharacter & 0x0fU);
            } else {
                output << static_cast<char>(kCharacter);
            }
            break;
        }
    }
    output << '"';
}

void renderFailure(std::ostream& output, const Failure& failure, OutputFormat format) {
    if (format == OutputFormat::Human) {
        output << failureCodeName(failure.code) << ": " << failure.path << ": " << failure.message << '\n';
        return;
    }

    output << "{\"ok\":false,\"code\":";
    writeJsonString(output, failureCodeName(failure.code));
    output << ",\"path\":";
    writeJsonString(output, failure.path);
    output << ",\"message\":";
    writeJsonString(output, failure.message);
    output << "}\n";
}

void renderSuccess(std::ostream& output, std::string_view operation, std::string_view details, OutputFormat format) {
    if (format == OutputFormat::Human) {
        output << operation << ": " << details << '\n';
        return;
    }

    output << "{\"ok\":true,\"operation\":";
    writeJsonString(output, operation);
    output << ",\"details\":";
    writeJsonString(output, details);
    output << "}\n";
}

} // namespace rawframe::tool::evidence
