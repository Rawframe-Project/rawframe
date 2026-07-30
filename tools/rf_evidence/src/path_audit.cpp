#include "path_audit.h"

#include "path_policy.h"

#include <algorithm>
#include <array>
#include <string_view>

namespace rawframe::tool::evidence {

namespace {

constexpr std::size_t kMaximumAuditedFiles = 65'536;

// The frozen write envelopes from the accepted Task Packets' "Allowed paths"
// sections, expressed as lowercase repository-relative paths. TASK-0001 and
// TASK-0002 are complete and TASK-0003 is active; a completed Task's output
// stays listed, because the audit reports what the envelope admits and not what
// is in flight. TASK-0003 adds no entry: every path it writes is either beneath
// the `tools/rf_evidence/` root below or beneath `out/`, which is skipped.
constexpr std::array kEnvelopeFiles{
    std::string_view{".gitignore"},
    // Root .clang-tidy joined the envelope through the accepted 2026-07-16
    // completion-review amendment (analysis-lane check policy only).
    std::string_view{".clang-tidy"},
    std::string_view{"cmakelists.txt"},
    std::string_view{"cmakepresets.json"},
    std::string_view{"repository.json"},
    std::string_view{"schemas/repository.schema.json"},
    std::string_view{"schemas/tool.schema.json"},
    std::string_view{"schemas/dependency-catalog.schema.json"},
    std::string_view{"schemas/toolchain-lock.schema.json"},
    std::string_view{"schemas/artifact-lock.schema.json"},
    // TASK-0002 envelope. The two evidence schemas are named individually
    // rather than admitted by the pre-existing schemas/*.schema.json rule,
    // because that rule classifies a schema as accepted pre-existing material
    // and would absorb this Task's own output without widening anything.
    std::string_view{"schemas/evidence-common-v1.schema.json"},
    std::string_view{"schemas/raw-run-receipt-v1.schema.json"},
    std::string_view{"schemas/attempt-plan-v1.schema.json"},
    std::string_view{"schemas/evidence-set-v1.schema.json"},
    // TASK-0005 envelope, named individually for the same reason.
    std::string_view{"schemas/evidence-index-v1.schema.json"},
    std::string_view{"schemas/metric-registry-v1.schema.json"},
    std::string_view{"schemas/evaluation-policy-v1.schema.json"},
    std::string_view{"schemas/evaluation-receipt-v1.schema.json"},
    // TASK-0007 envelope, named individually for the same reason.
    std::string_view{"schemas/baseline-record-v1.schema.json"},
    // TASK-0010 envelope, named individually for the same reason.
    std::string_view{"schemas/archcheck-rules-v1.schema.json"},
    std::string_view{"schemas/archcheck-findings-v1.schema.json"},
    std::string_view{"third_party/catalog.json"},
    std::string_view{"third_party/toolchain.lock.json"},
    std::string_view{"third_party/artifacts.lock.json"},
    std::string_view{"docs/readme.md"},
    std::string_view{"docs/plans/plan-0001-evidence-mechanics.md"},
    std::string_view{"docs/tasks/readme.md"},
    std::string_view{"docs/tasks/task-0001-repository-tool-bootstrap-and-offline-authority-validation.md"},
};

constexpr std::array kEnvelopeRoots{
    std::string_view{"cmake/"},
    std::string_view{"third_party/vcpkg/"},
    std::string_view{"third_party/licenses/"},
    std::string_view{"tools/rf_evidence/"},
    // TASK-0010 envelope: the second repository tool's root.
    std::string_view{"tools/rf_archcheck/"},
};

// Read-only material that legitimately coexists with the Task in the same
// repository: governance instructions, repository standards, the owner's
// handoff, the pre-existing documentation tree, and pre-existing schemas.
constexpr std::array kPreexistingFiles{
    std::string_view{"claude.md"},
    std::string_view{"readme.md"},
    std::string_view{"task-0001-handoff.md"},
    std::string_view{".clang-format"},
    std::string_view{".editorconfig"},
    std::string_view{".gitattributes"},
    std::string_view{"stylua.toml"},
};

// Root staging directories the accepted 2026-07-16 completion-review
// amendment classifies as historical/staging-only and landing-excluded:
// not delivered, never copied into the canonical project, left untouched.
constexpr std::array kStagingRoots{
    std::string_view{".agents"},
    std::string_view{".audit-import-stage"},
    std::string_view{".claude-memory-stage"},
    std::string_view{".codex"},
    std::string_view{".codex-doc-stage"},
    std::string_view{".codex-doc-stage-2"},
    std::string_view{".codex-doc-stage-3"},
    std::string_view{".docs-reset-staging"},
    std::string_view{".handoff-stage"},
    std::string_view{".remediation-stage"},
    std::string_view{".repo-standard-stage"},
};

constexpr std::array kPreexistingRoots{
    std::string_view{".claude/"},
    std::string_view{"docs/"},
};

constexpr std::array kSkippedRoots{
    std::string_view{".git"},
    std::string_view{"out"},
};

// Root `evidence/` is admitted as an envelope root, but not as a bare prefix.
// Maintained authorities and generated artifacts stay apart, and the difference
// between them is not a convention anyone has to remember: this rule admits the
// index and the two authority classes it can name, so a receipt, a blob, a
// report, a baseline, or anything nested deeper is reported rather than
// absorbed. Generated evidence belongs beneath `out/`, which is skipped.
bool matchesMaintainedEvidence(std::string_view relativePath) {
    if (relativePath == "evidence/evidence.json") {
        return true;
    }
    for (const std::string_view kClassRoot : {"evidence/registries/", "evidence/policies/"}) {
        if (!relativePath.starts_with(kClassRoot) || !relativePath.ends_with(".json")) {
            continue;
        }
        // One level below the class root and no further, so a directory tree
        // cannot grow underneath a name that looks maintained.
        return relativePath.find('/', kClassRoot.size()) == std::string_view::npos;
    }
    return false;
}

bool matchesEnvelope(std::string_view relativePath) {
    if (std::ranges::find(kEnvelopeFiles, relativePath) != kEnvelopeFiles.end()) {
        return true;
    }
    if (relativePath.starts_with("evidence/")) {
        return matchesMaintainedEvidence(relativePath);
    }
    return std::ranges::any_of(kEnvelopeRoots, [relativePath](std::string_view root) {
        return relativePath.starts_with(root);
    });
}

bool matchesPreexisting(std::string_view relativePath) {
    if (std::ranges::find(kPreexistingFiles, relativePath) != kPreexistingFiles.end()) {
        return true;
    }
    if (std::ranges::any_of(kPreexistingRoots, [relativePath](std::string_view root) {
            return relativePath.starts_with(root);
        })) {
        return true;
    }
    // Schemas not named in the envelope are accepted pre-existing
    // specification projections and remain read-only inputs.
    return relativePath.starts_with("schemas/") && relativePath.ends_with(".schema.json");
}

constexpr std::array kKnownTopDirectories{
    std::string_view{".claude"},
    std::string_view{"cmake"},
    std::string_view{"docs"},
    std::string_view{"evidence"},
    std::string_view{"schemas"},
    std::string_view{"third_party"},
    std::string_view{"tools"},
};

bool isKnownTopDirectory(std::string_view name) {
    return std::ranges::find(kKnownTopDirectories, name) != kKnownTopDirectories.end();
}

bool hasKnownTopComponent(std::string_view relativePath) {
    const auto kSeparator = relativePath.find('/');
    if (kSeparator == std::string_view::npos) {
        return false;
    }
    return isKnownTopDirectory(relativePath.substr(0, kSeparator));
}

} // namespace

Result<PathAudit> auditRepositoryPaths(const std::filesystem::path& repositoryRoot) {
    auto canonicalRoot = resolveRepositoryPath(repositoryRoot, "repository.json");
    if (!canonicalRoot) {
        return std::unexpected(canonicalRoot.error());
    }
    const auto kRoot = canonicalRoot->parent_path();

    PathAudit audit;
    std::size_t auditedFiles = 0;
    std::error_code error;
    for (std::filesystem::recursive_directory_iterator iterator(kRoot, error), end; iterator != end;
         iterator.increment(error)) {
        if (error) {
            return std::unexpected(
                Failure{FailureCode::IoFailure, kRoot.generic_string(), "failed to enumerate the repository"});
        }
        // Lexical, because this audit classifies paths as they exist in the
        // tree. `std::filesystem::relative` resolves symlinks, which would
        // report a link under the path of whatever it points at, and would
        // report a link that leaves the repository as a traversal path outside
        // it. The iterator descends from the canonical root, so for every
        // ordinary entry the two agree.
        const auto kRelative = iterator->path().lexically_relative(kRoot);
        const auto kRelativeText = portableLowercasePath(kRelative);

        if (iterator->is_symlink(error)) {
            audit.envelopeViolations.push_back(PathAuditEntry{kRelative.generic_string(), "symlink"});
            iterator.disable_recursion_pending();
            continue;
        }

        const bool kIsTopLevel = iterator.depth() == 0;
        if (kIsTopLevel && std::ranges::find(kSkippedRoots, kRelativeText) != kSkippedRoots.end()) {
            iterator.disable_recursion_pending();
            continue;
        }
        if (kIsTopLevel && std::ranges::find(kStagingRoots, kRelativeText) != kStagingRoots.end()) {
            audit.stagingRootEntries.push_back(
                PathAuditEntry{kRelative.generic_string(), "historical_staging_landing_excluded"});
            iterator.disable_recursion_pending();
            continue;
        }
        if (kIsTopLevel && iterator->is_directory(error) && !isKnownTopDirectory(kRelativeText)) {
            audit.unclassifiedRootEntries.push_back(PathAuditEntry{kRelative.generic_string(), "unclassified"});
            iterator.disable_recursion_pending();
            continue;
        }
        if (!iterator->is_regular_file(error)) {
            continue;
        }
        ++auditedFiles;
        if (auditedFiles > kMaximumAuditedFiles) {
            return std::unexpected(
                Failure{FailureCode::LimitExceeded, kRoot.generic_string(), "repository audit exceeds the file limit"});
        }

        if (matchesEnvelope(kRelativeText)) {
            ++audit.envelopeFileCount;
            audit.envelopeFiles.push_back(kRelative.generic_string());
        } else if (matchesPreexisting(kRelativeText)) {
            ++audit.preexistingFileCount;
        } else if (hasKnownTopComponent(kRelativeText)) {
            audit.envelopeViolations.push_back(PathAuditEntry{kRelative.generic_string(), "outside_envelope"});
        } else {
            audit.unclassifiedRootEntries.push_back(PathAuditEntry{kRelative.generic_string(), "unclassified"});
        }
    }

    std::ranges::sort(audit.envelopeViolations, {}, &PathAuditEntry::path);
    std::ranges::sort(audit.stagingRootEntries, {}, &PathAuditEntry::path);
    std::ranges::sort(audit.unclassifiedRootEntries, {}, &PathAuditEntry::path);
    std::ranges::sort(audit.envelopeFiles);
    return audit;
}

} // namespace rawframe::tool::evidence
