#pragma once

#include "diagnostic.h"
#include "failure.h"

#include <filesystem>
#include <iosfwd>
#include <optional>
#include <string>

namespace rawframe::tool::evidence {

// Everything the command line can say, parsed once. This lives here rather than
// in command.cpp because the operations below need it and the parser that
// produces it stays with the dispatch table. Not every operation reads every
// member; an operation that is handed one it has no use for rejects it rather
// than ignoring it.
struct ParsedOptions {
    std::filesystem::path repositoryRoot;
    std::optional<std::string> toolId;
    std::optional<std::string> hostId;
    std::optional<std::string> reportPath;
    std::optional<std::string> recordPath;
    std::optional<std::string> descriptorPath;
    std::optional<std::string> planPath;
    std::optional<std::string> setId;
    std::optional<std::string> setPath;
    std::optional<std::string> evaluationId;
    std::optional<std::string> sourcePath;
    std::optional<std::string> digest;
    std::optional<std::string> mediaType;
    OutputFormat format = OutputFormat::Human;
};

// Renders a failure and returns the process exit code for it. Shared by every
// operation on both sides of this split, so that one failure cannot exit with a
// different code depending on which file it was raised in.
[[nodiscard]] int fail(std::ostream& errors, const Failure& failure, OutputFormat format);

// The record and store operations. Each one resolves its arguments, calls the
// component that owns the behavior, and emits. None of them holds domain logic:
// canonical form belongs to canonical_json, record semantics to record_gate and
// the record's own component, and content addressing to blob_store.
[[nodiscard]] int canonicalizeOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors);
[[nodiscard]] int validateRecordOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors);
[[nodiscard]] int assembleOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors);

// Loads every maintained evidence authority the registered index names, gates
// each as a record, and resolves the policy against the registry generation it
// was written for. Membership is proven by repository validation, so an
// authority sitting under `evidence/` without being listed is refused rather
// than found. Nothing here evaluates an observation or reaches a verdict.
[[nodiscard]] int loadEvidenceIndexOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors);

// Evaluates one Evidence Set against the maintained registry and policy and
// emits an EvaluationReceipt. The registry and the policy are read from the
// repository's own index and never from an argument, because a verdict against
// a policy the caller supplied is a verdict about nothing.
//
// The exit code projects the verdict rather than being it: 0 for a receipt that
// passed, 4 for one that failed, and 3 when no receipt could be produced.
[[nodiscard]] int evaluateOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors);

[[nodiscard]] int putBlobOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors);
[[nodiscard]] int verifyBlobOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors);
[[nodiscard]] int getBlobOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors);

} // namespace rawframe::tool::evidence
