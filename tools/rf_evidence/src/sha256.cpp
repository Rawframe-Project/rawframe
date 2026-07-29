#include "sha256.h"

#include <array>
#include <fstream>
#include <memory>
#include <openssl/evp.h>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

namespace {

using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

// One computation shared by both entry points. Callers differ only in where the
// bytes come from, so the digest, the hex form, and every failure they can
// report are decided here once.
class Sha256Digest {
public:
    explicit Sha256Digest(std::string subject)
        : subject_(std::move(subject)), context_(EVP_MD_CTX_new(), &EVP_MD_CTX_free) {
    }

    [[nodiscard]] Status begin() {
        if (!context_ || EVP_DigestInit_ex(context_.get(), EVP_sha256(), nullptr) != 1) {
            return std::unexpected(Failure{FailureCode::VerificationFailed, subject_, "failed to initialize SHA-256"});
        }
        return {};
    }

    [[nodiscard]] Status update(const void* data, std::size_t length) {
        if (length == 0) {
            return {};
        }
        if (EVP_DigestUpdate(context_.get(), data, length) != 1) {
            return std::unexpected(Failure{FailureCode::VerificationFailed, subject_, "failed while hashing content"});
        }
        return {};
    }

    [[nodiscard]] Result<std::string> finish() {
        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int digestBytes = 0;
        if (EVP_DigestFinal_ex(context_.get(), digest.data(), &digestBytes) != 1 || digestBytes != 32U) {
            return std::unexpected(Failure{FailureCode::VerificationFailed, subject_, "failed to finalize SHA-256"});
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

private:
    std::string subject_;
    Context context_;
};

} // namespace

Result<std::string> sha256File(const std::filesystem::path& path) {
    Sha256Digest digest(path.generic_string());
    if (auto status = digest.begin(); !status) {
        return std::unexpected(status.error());
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
        if (kCount > 0) {
            if (auto status = digest.update(buffer.data(), static_cast<std::size_t>(kCount)); !status) {
                return std::unexpected(status.error());
            }
        }
    }
    if (!input.eof()) {
        return std::unexpected(
            Failure{FailureCode::IoFailure, path.generic_string(), "failed while reading cache object"});
    }
    return digest.finish();
}

Result<std::string> sha256Bytes(std::string_view bytes) {
    Sha256Digest digest("<memory>");
    if (auto status = digest.begin(); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = digest.update(bytes.data(), bytes.size()); !status) {
        return std::unexpected(status.error());
    }
    return digest.finish();
}

} // namespace rawframe::tool::evidence
