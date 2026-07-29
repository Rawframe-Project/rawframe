#include "sha256.h"

#include <array>
#include <fstream>
#include <openssl/evp.h>
#include <string_view>
#include <utility>
#include <vector>

namespace rawframe::tool::evidence {

namespace {

using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

} // namespace

// The provider lives entirely here. Callers see a subject string, three steps,
// and a hexadecimal result.
struct Sha256Stream::State {
    std::string subject;
    Context context;
    bool started = false;
    bool finished = false;
};

Sha256Stream::Sha256Stream(std::string subject)
    : state_(std::make_unique<State>(std::move(subject), Context{EVP_MD_CTX_new(), &EVP_MD_CTX_free})) {
}

Sha256Stream::~Sha256Stream() = default;
Sha256Stream::Sha256Stream(Sha256Stream&&) noexcept = default;
Sha256Stream& Sha256Stream::operator=(Sha256Stream&&) noexcept = default;

Status Sha256Stream::begin() {
    if (!state_->context || state_->started || EVP_DigestInit_ex(state_->context.get(), EVP_sha256(), nullptr) != 1) {
        return std::unexpected(
            Failure{FailureCode::VerificationFailed, state_->subject, "failed to initialize SHA-256"});
    }
    state_->started = true;
    return {};
}

Status Sha256Stream::update(std::string_view bytes) {
    if (!state_->started || state_->finished) {
        return std::unexpected(
            Failure{FailureCode::VerificationFailed, state_->subject, "SHA-256 stream is not accepting content"});
    }
    if (bytes.empty()) {
        return {};
    }
    if (EVP_DigestUpdate(state_->context.get(), bytes.data(), bytes.size()) != 1) {
        return std::unexpected(
            Failure{FailureCode::VerificationFailed, state_->subject, "failed while hashing content"});
    }
    return {};
}

Result<std::string> Sha256Stream::finish() {
    if (!state_->started || state_->finished) {
        return std::unexpected(
            Failure{FailureCode::VerificationFailed, state_->subject, "SHA-256 stream cannot be finished twice"});
    }
    state_->finished = true;

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digestBytes = 0;
    if (EVP_DigestFinal_ex(state_->context.get(), digest.data(), &digestBytes) != 1 || digestBytes != 32U) {
        return std::unexpected(Failure{FailureCode::VerificationFailed, state_->subject, "failed to finalize SHA-256"});
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

Result<std::string> sha256File(const std::filesystem::path& path) {
    Sha256Stream digest(path.generic_string());
    if (auto status = digest.begin(); !status) {
        return std::unexpected(status.error());
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::unexpected(Failure{FailureCode::MissingInput, path.generic_string(), "cache object is missing"});
    }

    std::vector<char> buffer(kSha256ChunkBytes);
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto kCount = input.gcount();
        if (kCount > 0) {
            const std::string_view kChunk{buffer.data(), static_cast<std::size_t>(kCount)};
            if (auto status = digest.update(kChunk); !status) {
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
    Sha256Stream digest("<memory>");
    if (auto status = digest.begin(); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = digest.update(bytes); !status) {
        return std::unexpected(status.error());
    }
    return digest.finish();
}

} // namespace rawframe::tool::evidence
