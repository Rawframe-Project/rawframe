#include "record_command.h"

#include "canonical_json.h"
#include "descriptor.h"
#include "evaluation_policy.h"
#include "evaluator.h"
#include "evidence_set.h"
#include "file_reader.h"
#include "metric_registry.h"
#include "raw_run_receipt.h"
#include "record_gate.h"
#include "repository_validator.h"
#include "store_command.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <ostream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace rawframe::tool::evidence {

namespace {

int failRecord(std::ostream& output, std::ostream& errors, const RecordFailure& failure, OutputFormat format) {
    if (format == OutputFormat::Json) {
        output << buildRejectionOutput(failure);
    }
    renderFailure(errors,
                  Failure{FailureCode::VerificationFailed, recordRejectionName(failure.rejection), failure.detail},
                  format);
    return 3;
}

// Shared by both record operations: a record is always read through the record
// byte ceiling rather than the maintained-JSON one, because these bytes are
// untrusted input and not a manifest this repository maintains.
Result<std::string> readRecordBytes(const std::filesystem::path& path) {
    auto input = readBoundedFile(path, kMaximumRecordBytes);
    if (!input) {
        return std::unexpected(input.error());
    }
    return std::string(std::string_view(input->data(), input->size()));
}

Result<std::filesystem::path>
resolveRecordArgument(const ParsedOptions& options, const std::optional<std::string>& argument, std::string_view flag) {
    if (!argument) {
        return std::unexpected(Failure{FailureCode::InvalidArguments, std::string(flag), "a record path is required"});
    }
    std::filesystem::path candidate(*argument);
    if (candidate.is_relative()) {
        candidate = options.repositoryRoot / candidate;
    }
    std::error_code error;
    auto resolved = std::filesystem::weakly_canonical(candidate, error);
    if (error) {
        return std::unexpected(Failure{FailureCode::InvalidPath, *argument, "failed to resolve the path"});
    }
    return resolved;
}

// Decision 1: the kind is read from the record's own bytes. A caller never
// supplies it, so no command line can relabel a record on its way past. Each
// kind carries its own media type and its own gate; nothing here is a default.
struct RecordKindBinding {
    std::string_view mediaType;
};

RecordResult<RecordKindBinding> bindRecordKind(const CanonicalValue& record) {
    auto kind = readRecordKind(record);
    if (!kind) {
        return std::unexpected(kind.error());
    }
    if (*kind == kRawRunReceiptRecordKind) {
        return RecordKindBinding{kRawRunReceiptMediaType};
    }
    if (*kind == kEvidenceSetRecordKind) {
        return RecordKindBinding{kEvidenceSetMediaType};
    }
    if (*kind == kAttemptPlanRecordKind) {
        return RecordKindBinding{kAttemptPlanMediaType};
    }
    if (*kind == kMetricRegistryRecordKind) {
        return RecordKindBinding{kMetricRegistryMediaType};
    }
    if (*kind == kEvaluationPolicyRecordKind) {
        return RecordKindBinding{kEvaluationPolicyMediaType};
    }
    if (*kind == kEvaluationReceiptRecordKind) {
        return RecordKindBinding{kEvaluationReceiptMediaType};
    }
    return std::unexpected(RecordFailure{RecordRejection::SchemaInvalid, "record declares an unknown kind: " + *kind});
}

// The semantic gate for whichever kind the record declared. A receipt is
// summarized; the other kinds are gated and reported by identity, because
// neither has a summary that means anything a caller would act on.
RecordResult<std::string> gateRecord(const std::filesystem::path& repositoryRoot,
                                     const std::filesystem::path& instancePath,
                                     const CanonicalValue& record,
                                     std::string_view mediaType) {
    if (mediaType == kRawRunReceiptMediaType) {
        auto summary = validateRawRunReceipt(repositoryRoot, instancePath, record, mediaType);
        if (!summary) {
            return std::unexpected(summary.error());
        }
        return summary->runId;
    }
    // The maintained authorities gate themselves, because their semantic checks
    // are not a subset of any other kind's. Their identity is the pair of kind
    // and generation rather than a UUID: neither is one occurrence of anything.
    if (mediaType == kMetricRegistryMediaType) {
        auto registry = parseMetricRegistry(repositoryRoot, instancePath, record);
        if (!registry) {
            return std::unexpected(registry.error());
        }
        return "metric registry generation " + std::to_string(registry->registryGeneration);
    }
    if (mediaType == kEvaluationPolicyMediaType) {
        auto policy = parseEvaluationPolicy(repositoryRoot, instancePath, record);
        if (!policy) {
            return std::unexpected(policy.error());
        }
        return "evaluation policy generation " + std::to_string(policy->policyGeneration);
    }
    // The EvaluationReceipt is gated before the producer-authority check rather
    // than after it. That check refuses any member naming an outcome, and this
    // record exists to state one: it is the single kind in the chain permitted
    // to, and holding it to a producer's restriction would make the verdict
    // authority unrepresentable.
    if (mediaType == kEvaluationReceiptMediaType) {
        if (auto status = checkRecordKind(record, kEvaluationReceiptRecordKind); !status) {
            return std::unexpected(status.error());
        }
        if (auto status = validateAgainstSchema(repositoryRoot, kEvaluationReceiptSchemaPath, instancePath); !status) {
            return std::unexpected(status.error());
        }
        if (auto status = checkGenerationMatches(record, mediaType, kEvaluationReceiptGeneration); !status) {
            return std::unexpected(status.error());
        }
        const auto* kIdentity = record.find("evaluationId");
        if (kIdentity == nullptr || kIdentity->kind() != CanonicalValue::Kind::String) {
            return std::unexpected(
                RecordFailure{RecordRejection::SchemaInvalid, "evaluation receipt carries no identity"});
        }
        return kIdentity->text();
    }
    if (auto status = checkProducerAuthority(record); !status) {
        return std::unexpected(status.error());
    }
    if (mediaType == kAttemptPlanMediaType) {
        auto plan = parseAttemptPlan(repositoryRoot, instancePath, record);
        if (!plan) {
            return std::unexpected(plan.error());
        }
        if (auto status = checkGenerationMatches(record, mediaType, kAttemptPlanGeneration); !status) {
            return std::unexpected(status.error());
        }
        return plan->planId;
    }
    if (auto status = checkRecordKind(record, kEvidenceSetRecordKind); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = validateAgainstSchema(repositoryRoot, kEvidenceSetSchemaPath, instancePath); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkGenerationMatches(record, mediaType, kEvidenceSetGeneration); !status) {
        return std::unexpected(status.error());
    }
    const auto* kIdentity = record.find("evidenceSetId");
    if (kIdentity == nullptr || kIdentity->kind() != CanonicalValue::Kind::String) {
        return std::unexpected(RecordFailure{RecordRejection::SchemaInvalid, "evidence set carries no identity"});
    }
    return kIdentity->text();
}

} // namespace

int fail(std::ostream& errors, const Failure& failure, OutputFormat format) {
    renderFailure(errors, failure, format);
    return failure.code == FailureCode::InvalidArguments ? 2 : 3;
}

int canonicalizeOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    auto recordPath = resolveRecordArgument(options, options.recordPath, "--record");
    if (!recordPath) {
        return fail(errors, recordPath.error(), options.format);
    }
    auto bytes = readRecordBytes(*recordPath);
    if (!bytes) {
        return fail(errors, bytes.error(), options.format);
    }
    // Authored input, so it is parsed rather than ingested: it is not required
    // to already be canonical, which is the whole point of this operation.
    auto parsed = parseCanonicalSubset(*bytes);
    if (!parsed) {
        return failRecord(output, errors, parsed.error(), options.format);
    }
    const std::string kCanonical = serializeCanonical(*parsed);
    auto binding = bindRecordKind(*parsed);
    if (!binding) {
        return failRecord(output, errors, binding.error(), options.format);
    }
    auto descriptor = describeBytes(kCanonical, binding->mediaType);
    if (!descriptor) {
        return failRecord(output, errors, descriptor.error(), options.format);
    }
    auto identity = gateRecord(options.repositoryRoot, *recordPath, *parsed, descriptor->mediaType);
    if (!identity) {
        return failRecord(output, errors, identity.error(), options.format);
    }
    if (options.format == OutputFormat::Json) {
        if (binding->mediaType == kRawRunReceiptMediaType) {
            auto summary = summarizeRawRunReceipt(*parsed);
            if (!summary) {
                return failRecord(output, errors, summary.error(), options.format);
            }
            output << buildCanonicalizeOutput(*descriptor, *summary);
            return 0;
        }
        if (binding->mediaType == kEvidenceSetMediaType) {
            output << buildEvidenceSetOutput(*descriptor, *parsed, "canonicalize");
            return 0;
        }
        output << serializeCanonical(describeAsValue(*descriptor));
        return 0;
    }
    // The bytes themselves, exactly, with nothing appended. A trailing newline
    // here would be a byte this repository's canonical form does not have.
    output << kCanonical;
    return 0;
}

int validateRecordOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    auto recordPath = resolveRecordArgument(options, options.recordPath, "--record");
    if (!recordPath) {
        return fail(errors, recordPath.error(), options.format);
    }
    auto bytes = readRecordBytes(*recordPath);
    if (!bytes) {
        return fail(errors, bytes.error(), options.format);
    }
    auto record = ingestCanonicalBytes(*bytes);
    if (!record) {
        return failRecord(output, errors, record.error(), options.format);
    }

    auto binding = bindRecordKind(*record);
    if (!binding) {
        return failRecord(output, errors, binding.error(), options.format);
    }
    const std::string_view kMediaType = binding->mediaType;

    Descriptor descriptor{std::string(kMediaType), bytes->size(), {}};
    if (options.descriptorPath) {
        auto descriptorPath = resolveRecordArgument(options, options.descriptorPath, "--descriptor");
        if (!descriptorPath) {
            return fail(errors, descriptorPath.error(), options.format);
        }
        auto descriptorBytes = readRecordBytes(*descriptorPath);
        if (!descriptorBytes) {
            return fail(errors, descriptorBytes.error(), options.format);
        }
        auto descriptorValue = ingestCanonicalBytes(*descriptorBytes);
        if (!descriptorValue) {
            return failRecord(output, errors, descriptorValue.error(), options.format);
        }
        auto supplied = parseDescriptor(*descriptorValue);
        if (!supplied) {
            return failRecord(output, errors, supplied.error(), options.format);
        }
        if (auto status = verifyDescriptor(*supplied, *bytes, kMediaType); !status) {
            return failRecord(output, errors, status.error(), options.format);
        }
        descriptor = *supplied;
    } else {
        auto computed = describeBytes(*bytes, kMediaType);
        if (!computed) {
            return failRecord(output, errors, computed.error(), options.format);
        }
        descriptor = *computed;
    }

    auto identity = gateRecord(options.repositoryRoot, *recordPath, *record, descriptor.mediaType);
    if (!identity) {
        return failRecord(output, errors, identity.error(), options.format);
    }
    if (options.format == OutputFormat::Json) {
        if (kMediaType == kRawRunReceiptMediaType) {
            auto summary = summarizeRawRunReceipt(*record);
            if (!summary) {
                return failRecord(output, errors, summary.error(), options.format);
            }
            output << buildValidateOutput(descriptor, *summary);
            return 0;
        }
        if (kMediaType == kEvidenceSetMediaType) {
            output << buildEvidenceSetOutput(descriptor, *record, "validate");
            return 0;
        }
        output << serializeCanonical(describeAsValue(descriptor));
        return 0;
    }
    renderSuccess(output, "validate_record", *identity + " is canonical and valid", options.format);
    return 0;
}

// Assembly reads a declared plan, retrieves each named receipt from the store,
// and emits one ledger. It writes nothing: the bytes go to standard output and
// a caller stores them with `put blob`, which keeps the thing that produces
// evidence separate from the thing that holds it.
int assembleOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    auto planPath = resolveRecordArgument(options, options.planPath, "--plan");
    if (!planPath) {
        return fail(errors, planPath.error(), options.format);
    }
    auto bytes = readRecordBytes(*planPath);
    if (!bytes) {
        return fail(errors, bytes.error(), options.format);
    }
    auto plan = ingestCanonicalBytes(*bytes);
    if (!plan) {
        return failRecord(output, errors, plan.error(), options.format);
    }
    auto parsed = parseAttemptPlan(options.repositoryRoot, *planPath, *plan);
    if (!parsed) {
        return failRecord(output, errors, parsed.error(), options.format);
    }
    // The set's own identity is supplied rather than derived. Deriving it from
    // the content would make two assemblies of the same schedule the same
    // record, which they are not: they are two assemblies.
    if (!options.setId) {
        return fail(errors,
                    Failure{FailureCode::InvalidArguments, "--set-id", "an evidence set identity is required"},
                    options.format);
    }
    const BlobStore kStore = storeFor(options);
    auto assembled = assembleEvidenceSet(kStore, *parsed, *options.setId);
    if (!assembled) {
        return failRecord(output, errors, assembled.error(), options.format);
    }
    output << serializeCanonical(*assembled);
    return 0;
}

// Every maintained authority the registered index names, each gated as a
// record and each carrying the descriptor of the exact bytes that were read.
// Two operations need this and they differ only in what they do with it, so it
// is loaded once here rather than twice: a second loader would be a second
// authority for what the repository maintains.
struct LoadedAuthorities {
    std::vector<MetricRegistry> registries;
    std::vector<Descriptor> registryDescriptors;
    std::vector<EvaluationPolicy> policies;
    std::vector<Descriptor> policyDescriptors;
    std::size_t metricCount = 0;
    std::size_t boundEntryCount = 0;
};

// Renders its own failure and reports the exit code through `exitCode`, because
// the callers differ in what they produce on success and not at all in what a
// load failure should look like.
std::optional<LoadedAuthorities> loadAuthorities(const ParsedOptions& options,
                                                 const RepositorySnapshot& snapshot,
                                                 std::ostream& output,
                                                 std::ostream& errors,
                                                 int& exitCode) {
    LoadedAuthorities loaded;
    for (const auto& authority : snapshot.evidenceAuthorities) {
        const std::filesystem::path kPath = snapshot.root / std::filesystem::path(authority.path);
        auto bytes = readRecordBytes(kPath);
        if (!bytes) {
            exitCode = fail(errors, bytes.error(), options.format);
            return std::nullopt;
        }
        // Maintained authorities are held to the canonical form they claim.
        // Parsing them leniently and reserializing would repair them, and a
        // repaired authority is one nobody reviewed.
        auto record = ingestCanonicalBytes(*bytes);
        if (!record) {
            exitCode = failRecord(output, errors, record.error(), options.format);
            return std::nullopt;
        }
        auto descriptor = describeBytes(*bytes, authority.mediaType);
        if (!descriptor) {
            exitCode = failRecord(output, errors, descriptor.error(), options.format);
            return std::nullopt;
        }
        if (authority.authorityClass == "metric_registry") {
            auto registry = parseMetricRegistry(options.repositoryRoot, kPath, *record);
            if (!registry) {
                exitCode = failRecord(output, errors, registry.error(), options.format);
                return std::nullopt;
            }
            loaded.metricCount += registry->metrics.size();
            loaded.registries.push_back(std::move(*registry));
            loaded.registryDescriptors.push_back(std::move(*descriptor));
            continue;
        }
        auto policy = parseEvaluationPolicy(options.repositoryRoot, kPath, *record);
        if (!policy) {
            exitCode = failRecord(output, errors, policy.error(), options.format);
            return std::nullopt;
        }
        loaded.policies.push_back(std::move(*policy));
        loaded.policyDescriptors.push_back(std::move(*descriptor));
    }

    for (const auto& policy : loaded.policies) {
        const MetricRegistry* match = nullptr;
        for (const auto& candidate : loaded.registries) {
            if (candidate.registryGeneration != policy.metricRegistryGeneration) {
                continue;
            }
            if (match != nullptr) {
                exitCode =
                    failRecord(output,
                               errors,
                               RecordFailure{RecordRejection::SchemaInvalid, "two registries claim one generation"},
                               options.format);
                return std::nullopt;
            }
            match = &candidate;
        }
        if (match == nullptr) {
            exitCode = failRecord(
                output,
                errors,
                RecordFailure{RecordRejection::SchemaInvalid, "no registry exists at the generation a policy names"},
                options.format);
            return std::nullopt;
        }
        auto bound = bindPolicyToRegistry(policy, *match);
        if (!bound) {
            exitCode = failRecord(output, errors, bound.error(), options.format);
            return std::nullopt;
        }
        loaded.boundEntryCount += bound->size();
    }
    return loaded;
}

int loadEvidenceIndexOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    // Membership first. Repository validation proves the index resolves, is an
    // ordinary file, lists nothing twice, and leaves nothing under `evidence/`
    // unaccounted for. Loading a file this has not admitted is the one thing a
    // scanning loader would do and an explicit one must not.
    auto snapshot = validateRepository(options.repositoryRoot);
    if (!snapshot) {
        return fail(errors, snapshot.error(), options.format);
    }

    int exitCode = 0;
    auto loaded = loadAuthorities(options, *snapshot, output, errors, exitCode);
    if (!loaded) {
        return exitCode;
    }

    if (options.format == OutputFormat::Json) {
        std::vector<CanonicalValue::Member> members;
        members.emplace_back("index", CanonicalValue::makeString(snapshot->evidenceIndexPath));
        members.emplace_back(
            "authorityCount",
            CanonicalValue::makeInteger(static_cast<std::int64_t>(snapshot->evidenceAuthorities.size())));
        members.emplace_back("metricCount",
                             CanonicalValue::makeInteger(static_cast<std::int64_t>(loaded->metricCount)));
        members.emplace_back("boundEntryCount",
                             CanonicalValue::makeInteger(static_cast<std::int64_t>(loaded->boundEntryCount)));
        members.emplace_back("ok", CanonicalValue::makeBoolean(true));
        output << serializeCanonical(CanonicalValue::makeObject(std::move(members)));
        return 0;
    }
    renderSuccess(output,
                  "load_evidence_index",
                  std::to_string(snapshot->evidenceAuthorities.size()) + " maintained evidence authority(ies) valid, " +
                      std::to_string(loaded->boundEntryCount) + " policy entry(ies) bound",
                  options.format);
    return 0;
}

// Evaluation reads one Evidence Set, the receipts it names, and the maintained
// registry and policy, and emits one EvaluationReceipt on standard output. It
// writes no file, exactly as assembly does not: a caller stores the bytes with
// `put blob`, which keeps the thing that decides separate from the thing that
// holds what it decided.
//
// The exit code projects the verdict and is not the verdict. 0 is a receipt
// whose checks all passed, 4 is a receipt whose verdict is failed, and 3 is no
// receipt at all because nothing could be evaluated. A caller that needs the
// reason reads the record, which is the authority.
int evaluateOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    if (!options.evaluationId) {
        return fail(errors,
                    Failure{FailureCode::InvalidArguments, "--evaluation-id", "an evaluation identity is required"},
                    options.format);
    }
    auto setPath = resolveRecordArgument(options, options.setPath, "--set");
    if (!setPath) {
        return fail(errors, setPath.error(), options.format);
    }

    auto snapshot = validateRepository(options.repositoryRoot);
    if (!snapshot) {
        return fail(errors, snapshot.error(), options.format);
    }
    int exitCode = 0;
    auto loaded = loadAuthorities(options, *snapshot, output, errors, exitCode);
    if (!loaded) {
        return exitCode;
    }
    // The registry and the policy come from the repository's own index rather
    // than from arguments. A caller that could name a policy could bring a
    // permissive one, and a verdict against a policy the caller chose is a
    // verdict about nothing.
    if (loaded->policies.size() != 1) {
        return failRecord(
            output,
            errors,
            RecordFailure{RecordRejection::SchemaInvalid, "evaluation needs exactly one maintained evaluation policy"},
            options.format);
    }
    const EvaluationPolicy& kPolicy = loaded->policies.front();
    const MetricRegistry* registry = nullptr;
    const Descriptor* registryDescriptor = nullptr;
    for (std::size_t index = 0; index < loaded->registries.size(); ++index) {
        if (loaded->registries.at(index).registryGeneration != kPolicy.metricRegistryGeneration) {
            continue;
        }
        registry = &loaded->registries.at(index);
        registryDescriptor = &loaded->registryDescriptors.at(index);
    }
    if (registry == nullptr || registryDescriptor == nullptr) {
        return failRecord(
            output,
            errors,
            RecordFailure{RecordRejection::SchemaInvalid, "no registry exists at the generation the policy names"},
            options.format);
    }

    auto bytes = readRecordBytes(*setPath);
    if (!bytes) {
        return fail(errors, bytes.error(), options.format);
    }
    auto descriptor = describeBytes(*bytes, kEvidenceSetMediaType);
    if (!descriptor) {
        return failRecord(output, errors, descriptor.error(), options.format);
    }
    auto evidenceSet = ingestCanonicalBytes(*bytes);
    if (!evidenceSet) {
        return failRecord(output, errors, evidenceSet.error(), options.format);
    }

    const EvaluationInputs kInputs{.repositoryRoot = options.repositoryRoot,
                                   .evidenceSetPath = *setPath,
                                   .evidenceSetDescriptor = *descriptor,
                                   .metricRegistryDescriptor = *registryDescriptor,
                                   .evaluationPolicyDescriptor = loaded->policyDescriptors.front()};
    const BlobStore kStore = storeFor(options);
    auto receipt = evaluateEvidenceSet(kStore, kInputs, *evidenceSet, *registry, kPolicy, *options.evaluationId);
    if (!receipt) {
        return failRecord(output, errors, receipt.error(), options.format);
    }
    output << serializeCanonical(*receipt);

    const auto* kVerdict = receipt->find("verdict");
    const auto* kOutcome = kVerdict == nullptr ? nullptr : kVerdict->find("outcome");
    return kOutcome != nullptr && kOutcome->text() == "failed" ? 4 : 0;
}

} // namespace rawframe::tool::evidence
