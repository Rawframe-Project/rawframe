#include "sha256.h"

#include <array>
#include <fstream>
#include <memory>
#include <openssl/evp.h>
#include <span>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

Result<std::string> sha256File(const std::filesystem::path& path) {
    using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Context context(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
        return std::unexpected(
            Failure{FailureCode::VerificationFailed, path.generic_string(), "failed to initialize SHA-256"});
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::unexpected(Failure{FailureCode::MissingInput, path.generic_string(), "cache object is missing"});
    }

    // Heap-allocated: a 1 MiB stack buffer overflows the 1 MiB default
    // Windows thread stack.
    std::vector<char> buffer(1'048'576);
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto kCount = input.gcount();
        if (kCount > 0 && EVP_DigestUpdate(context.get(), buffer.data(), static_cast<std::size_t>(kCount)) != 1) {
            return std::unexpected(
                Failure{FailureCode::VerificationFailed, path.generic_string(), "failed while hashing cache object"});
        }
    }
    if (!input.eof()) {
        return std::unexpected(
            Failure{FailureCode::IoFailure, path.generic_string(), "failed while reading cache object"});
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestBytes = 0;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digestBytes) != 1 || digestBytes != 32U) {
        return std::unexpected(
            Failure{FailureCode::VerificationFailed, path.generic_string(), "failed to finalize SHA-256"});
    }

    constexpr std::string_view kHex = "0123456789abcdef";
    const auto kDigestLength = static_cast<std::size_t>(digestBytes);
    std::string result;
    result.resize(kDigestLength * 2U);
    for (std::size_t index = 0; index < kDigestLength; ++index) {
        result.at(index * 2U) = kHex.at(digest.at(index) >> 4U);
        result.at((index * 2U) + 1U) = kHex.at(digest.at(index) & 0x0fU);
    }
    return result;
}

} // namespace rawframe::tool::evidence
