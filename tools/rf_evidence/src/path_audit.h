#pragma once

#include "failure.h"

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace rawframe::tool::evidence {

struct PathAuditEntry {
    std::string path;
    std::string classification;
};

struct PathAudit {
    // Delivered material found outside the frozen TASK-0001 write envelope.
    // Any entry here is a blocking violation.
    std::vector<PathAuditEntry> envelopeViolations;
    // Top-level workspace entries this Task neither delivers nor reads as
    // authority. They are reported for the landing review and must be absent
    // from the canonical repository, but they do not fail a workspace audit.
    std::vector<PathAuditEntry> unclassifiedRootEntries;
    // Root staging directories the accepted 2026-07-16 amendment classifies
    // as historical/staging-only and landing-excluded; untouched, undelivered.
    std::vector<PathAuditEntry> stagingRootEntries;
    // The exact delivered-file list: every maintained file inside the frozen
    // write envelope, sorted, as the landing review's file inventory.
    std::vector<std::string> envelopeFiles;
    std::size_t envelopeFileCount = 0;
    std::size_t preexistingFileCount = 0;
};

// Walks the repository and classifies every maintained file against the
// frozen TASK-0001 write envelope and the known read-only authority material.
[[nodiscard]] Result<PathAudit> auditRepositoryPaths(const std::filesystem::path& repositoryRoot);

} // namespace rawframe::tool::evidence
