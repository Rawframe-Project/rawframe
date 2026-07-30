#include "repository_scan.h"

#include "tool_limits.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <system_error>
#include <utility>

namespace rawframe::tool::archcheck {

namespace {

std::unexpected<Failure> reject(FailureCode code, std::string path, std::string message) {
    return std::unexpected(Failure{code, std::move(path), std::move(message)});
}

constexpr std::array kUnwalkedRoots{
    std::string_view{".git"},
    std::string_view{"out"},
};

bool isUnwalked(std::string_view name) {
    return std::ranges::any_of(kUnwalkedRoots, [name](std::string_view root) {
        return root == name;
    });
}

// A name a repository-relative path may carry. Anything else is refused rather
// than normalized, because the checks compare paths as text and a path that
// compares differently on two hosts would make one host's result unreachable on
// the other.
bool isAdmissibleName(std::string_view name) {
    if (name.empty() || name == "." || name == "..") {
        return false;
    }
    if (name.size() > kMaximumPathLength) {
        return false;
    }
    return std::ranges::all_of(name, [](char character) {
        const auto kByte = static_cast<unsigned char>(character);
        if (kByte < 0x20U || kByte == 0x7FU) {
            return false;
        }
        return character != '\\' && character != ':' && character != '*' && character != '?' && character != '"' &&
               character != '<' && character != '>' && character != '|';
    });
}

Status walk(const std::filesystem::path& root,
            const std::filesystem::path& directory,
            const std::string& prefix,
            std::size_t depth,
            RepositoryScan& scan) {
    if (depth > kMaximumDirectoryDepth) {
        return reject(FailureCode::LimitExceeded, prefix, "directory nesting exceeds the depth limit");
    }
    std::error_code code;
    std::vector<std::filesystem::directory_entry> entries;
    for (std::filesystem::directory_iterator iterator(directory, std::filesystem::directory_options::none, code);
         iterator != std::filesystem::directory_iterator();
         iterator.increment(code)) {
        if (code) {
            return reject(FailureCode::IoFailure, prefix, "cannot enumerate the directory");
        }
        entries.push_back(*iterator);
    }
    if (code) {
        return reject(FailureCode::IoFailure, prefix, "cannot enumerate the directory");
    }
    // The single point where filesystem order stops mattering.
    std::ranges::sort(entries,
                      [](const std::filesystem::directory_entry& left, const std::filesystem::directory_entry& right) {
                          return left.path().filename().generic_string() < right.path().filename().generic_string();
                      });

    for (const auto& entry : entries) {
        const std::string kName = entry.path().filename().generic_string();
        if (prefix.empty() && isUnwalked(kName)) {
            continue;
        }
        if (!isAdmissibleName(kName)) {
            return reject(FailureCode::InvalidPath, prefix + kName, "the name is not an admissible path component");
        }
        const std::string kRelative = prefix + kName;
        if (kRelative.size() > kMaximumPathLength) {
            return reject(FailureCode::LimitExceeded, kRelative, "the path exceeds the path length limit");
        }
        const auto kStatus = entry.symlink_status(code);
        if (code) {
            return reject(FailureCode::IoFailure, kRelative, "cannot stat the entry");
        }
        if (std::filesystem::is_symlink(kStatus)) {
            return reject(FailureCode::InvalidPath, kRelative, "the entry is a link");
        }
        if (std::filesystem::is_directory(kStatus)) {
            scan.directories.push_back(kRelative);
            if (auto status = walk(root, entry.path(), kRelative + "/", depth + 1, scan); !status) {
                return status;
            }
            continue;
        }
        if (!std::filesystem::is_regular_file(kStatus)) {
            return reject(FailureCode::InvalidPath, kRelative, "the entry is not an ordinary file");
        }
        if (scan.files.size() >= kMaximumScannedFiles) {
            return reject(FailureCode::LimitExceeded, kRelative, "the tree exceeds the scanned file limit");
        }
        const auto kSize = entry.file_size(code);
        if (code) {
            return reject(FailureCode::IoFailure, kRelative, "cannot size the entry");
        }
        scan.files.push_back(ScannedFile{kRelative, static_cast<std::size_t>(kSize)});
    }
    return {};
}

} // namespace

bool RepositoryScan::hasFile(std::string_view path) const noexcept {
    return std::ranges::any_of(files, [path](const ScannedFile& file) {
        return file.path == path;
    });
}

bool RepositoryScan::hasDirectory(std::string_view path) const noexcept {
    return std::ranges::any_of(directories, [path](const std::string& entry) {
        return entry == path;
    });
}

Result<RepositoryScan> scanRepository(const std::filesystem::path& root) {
    std::error_code code;
    if (!std::filesystem::is_directory(root, code) || code) {
        return reject(FailureCode::MissingInput, root.generic_string(), "the repository root is not a directory");
    }
    RepositoryScan scan;
    scan.root = root;
    if (auto status = walk(root, root, {}, 0, scan); !status) {
        return std::unexpected(status.error());
    }
    // The walk already emits each directory in order, but the file list is built
    // depth first, so it is ordered once here and never again.
    std::ranges::sort(scan.files, [](const ScannedFile& left, const ScannedFile& right) {
        return left.path < right.path;
    });
    std::ranges::sort(scan.directories);
    return scan;
}

Result<std::string> readTextFile(const std::filesystem::path& path) {
    std::error_code code;
    const auto kStatus = std::filesystem::symlink_status(path, code);
    if (code || !std::filesystem::is_regular_file(kStatus)) {
        return reject(FailureCode::MissingInput, path.generic_string(), "the path is not an ordinary file");
    }
    const auto kSize = std::filesystem::file_size(path, code);
    if (code) {
        return reject(FailureCode::IoFailure, path.generic_string(), "cannot size the file");
    }
    if (kSize > kMaximumFileBytes) {
        return reject(FailureCode::LimitExceeded, path.generic_string(), "the file exceeds the byte limit");
    }
    std::FILE* handle = nullptr;
#ifdef _WIN32
    if (::_wfopen_s(&handle, path.c_str(), L"rb") != 0 || handle == nullptr) {
        return reject(FailureCode::IoFailure, path.generic_string(), "cannot open the file");
    }
#else
    handle = std::fopen(path.c_str(), "rb");
    if (handle == nullptr) {
        return reject(FailureCode::IoFailure, path.generic_string(), "cannot open the file");
    }
#endif
    std::string raw;
    raw.resize(static_cast<std::size_t>(kSize));
    const std::size_t kRead = std::fread(raw.data(), 1, raw.size(), handle);
    const bool kFailed = std::ferror(handle) != 0;
    (void)std::fclose(handle);
    if (kFailed || kRead != raw.size()) {
        return reject(FailureCode::IoFailure, path.generic_string(), "cannot read the file");
    }
    std::string text;
    text.reserve(raw.size());
    for (std::size_t index = 0; index < raw.size(); ++index) {
        if (raw.at(index) == '\r' && index + 1 < raw.size() && raw.at(index + 1) == '\n') {
            continue;
        }
        text.push_back(raw.at(index));
    }
    return text;
}

std::string_view fileExtension(std::string_view relativePath) noexcept {
    const auto kSlash = relativePath.find_last_of('/');
    const std::string_view kName = kSlash == std::string_view::npos ? relativePath : relativePath.substr(kSlash + 1);
    const auto kDot = kName.find_last_of('.');
    if (kDot == std::string_view::npos || kDot == 0) {
        return {};
    }
    return kName.substr(kDot);
}

bool isBuildFile(std::string_view relativePath) noexcept {
    const auto kSlash = relativePath.find_last_of('/');
    const std::string_view kName = kSlash == std::string_view::npos ? relativePath : relativePath.substr(kSlash + 1);
    return kName == "CMakeLists.txt" || fileExtension(relativePath) == ".cmake";
}

bool isFirstPartySource(std::string_view relativePath) noexcept {
    const std::string_view kExtension = fileExtension(relativePath);
    const bool kNativeExtension = kExtension == ".cpp" || kExtension == ".h";
    if (!kNativeExtension) {
        return false;
    }
    // First-party native source lives under a repository tool or, once modules
    // exist, under the production source root. Vendored trees are excluded by
    // name rather than by guessing from content.
    return relativePath.starts_with("tools/") || relativePath.starts_with("source/");
}

} // namespace rawframe::tool::archcheck
