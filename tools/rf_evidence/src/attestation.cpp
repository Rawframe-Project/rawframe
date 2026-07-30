#include "attestation.h"

#include "file_reader.h"
#include "process_runner.h"
#include "sha256.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <system_error>
#include <utility>

namespace rawframe::tool::evidence {

namespace {

constexpr std::string_view kDigestPrefix = "sha256:";
constexpr std::chrono::milliseconds kVerifierTimeout{120'000};

std::unexpected<AttestationFailure> refuse(AttestationRejection rejection, std::string detail) {
    return std::unexpected(AttestationFailure{rejection, std::move(detail)});
}

// Standard base64 with padding, which is what a DSSE payload uses. The URL-safe
// alphabet is not accepted, because accepting both would mean two encodings
// produce the same statement and a reader would have to guess which was meant.
AttestationResult<std::string> decodeBase64(std::string_view encoded) {
    static constexpr std::array<std::int8_t, 256> kReverse = [] {
        std::array<std::int8_t, 256> table{};
        table.fill(-1);
        constexpr std::string_view kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (std::size_t index = 0; index < kAlphabet.size(); ++index) {
            table.at(static_cast<unsigned char>(kAlphabet.at(index))) = static_cast<std::int8_t>(index);
        }
        return table;
    }();

    if (encoded.empty() || (encoded.size() % 4U) != 0U) {
        return refuse(AttestationRejection::BundleMalformed, "payload is not a padded base64 quantum sequence");
    }
    if (encoded.size() > kMaximumBundleBytes) {
        return refuse(AttestationRejection::BundleMalformed, "payload exceeds the accepted bundle ceiling");
    }

    std::string decoded;
    decoded.reserve((encoded.size() / 4U) * 3U);
    for (std::size_t offset = 0; offset < encoded.size(); offset += 4U) {
        std::array<std::int8_t, 4> quantum{};
        std::size_t padding = 0;
        for (std::size_t index = 0; index < 4U; ++index) {
            const char kCharacter = encoded.at(offset + index);
            if (kCharacter == '=') {
                // Padding is only ever the last one or two characters of the
                // last quantum. Anywhere else it is a second encoding of the
                // same bytes, which is exactly what canonical form forbids.
                if (offset + 4U != encoded.size() || index < 2U) {
                    return refuse(AttestationRejection::BundleMalformed, "payload padding is misplaced");
                }
                ++padding;
                quantum.at(index) = 0;
                continue;
            }
            if (padding != 0) {
                return refuse(AttestationRejection::BundleMalformed, "payload has data after padding");
            }
            const std::int8_t kValue = kReverse.at(static_cast<unsigned char>(kCharacter));
            if (kValue < 0) {
                return refuse(AttestationRejection::BundleMalformed, "payload carries a character outside base64");
            }
            quantum.at(index) = kValue;
        }
        const std::uint32_t kTriple =
            (static_cast<std::uint32_t>(quantum.at(0)) << 18U) | (static_cast<std::uint32_t>(quantum.at(1)) << 12U) |
            (static_cast<std::uint32_t>(quantum.at(2)) << 6U) | static_cast<std::uint32_t>(quantum.at(3));
        decoded.push_back(static_cast<char>((kTriple >> 16U) & 0xFFU));
        if (padding < 2U) {
            decoded.push_back(static_cast<char>((kTriple >> 8U) & 0xFFU));
        }
        if (padding < 1U) {
            decoded.push_back(static_cast<char>(kTriple & 0xFFU));
        }
    }
    return decoded;
}

AttestationResult<std::string>
requireString(const CanonicalValue& parent, std::string_view name, AttestationRejection rejection) {
    const CanonicalValue* member = parent.find(name);
    if (member == nullptr || member->kind() != CanonicalValue::Kind::String) {
        return refuse(rejection, "missing string member: " + std::string(name));
    }
    return member->text();
}

AttestationResult<const CanonicalValue*>
requireObject(const CanonicalValue& parent, std::string_view name, AttestationRejection rejection) {
    const CanonicalValue* member = parent.find(name);
    if (member == nullptr || member->kind() != CanonicalValue::Kind::Object) {
        return refuse(rejection, "missing object member: " + std::string(name));
    }
    return member;
}

// Isolates one top-level member's value text out of a bundle.
//
// This exists because a Sigstore bundle is not a Rawframe record and the
// canonical-record reader is the wrong reader for it. That reader enforces the
// limits maintained records live under, and one of them, a four-kilobyte
// ceiling on any single string, is smaller than what a genuine bundle carries:
// the first real one this lane produced has a 5,292-character transparency-log
// body under `verificationMaterial`. Raising the record ceiling to admit a
// foreign artifact would weaken every maintained record to accommodate
// something that is not one.
//
// So the part of the bundle that carries meaning is isolated first and parsed
// on its own. The isolated `dsseEnvelope` is small, well inside every record
// limit, and is still read by the one reader that owns parsing. Everything this
// skips over, the certificate chain and the log entries, is material Cosign
// verifies cryptographically and this code never interprets.
//
// The work is bounded by the bundle ceiling checked before this is reached, and
// the scan is deliberately not a JSON reader: it tracks strings, escapes, and
// nesting only far enough to find where one value ends, and refuses anything it
// cannot account for rather than guessing.
AttestationResult<std::string_view> extractTopLevelValue(std::string_view document, std::string_view name) {
    if (document.size() < 2U || document.front() != '{' || document.back() != '}') {
        return refuse(AttestationRejection::BundleMalformed, "the bundle is not one JSON object");
    }
    const auto kIsSpace = [](char character) {
        return character == ' ' || character == '\t' || character == '\n' || character == '\r';
    };

    std::size_t offset = 1;
    while (offset < document.size()) {
        while (offset < document.size() && kIsSpace(document.at(offset))) {
            ++offset;
        }
        if (offset >= document.size() || document.at(offset) == '}') {
            break;
        }
        if (document.at(offset) == ',') {
            ++offset;
            continue;
        }
        if (document.at(offset) != '"') {
            return refuse(AttestationRejection::BundleMalformed, "a bundle member name is not a string");
        }

        const std::size_t kKeyStart = offset + 1U;
        ++offset;
        while (offset < document.size() && document.at(offset) != '"') {
            offset += document.at(offset) == '\\' ? 2U : 1U;
        }
        if (offset >= document.size()) {
            return refuse(AttestationRejection::BundleMalformed, "a bundle member name is unterminated");
        }
        const std::string_view kKey = document.substr(kKeyStart, offset - kKeyStart);
        ++offset;

        while (offset < document.size() && kIsSpace(document.at(offset))) {
            ++offset;
        }
        if (offset >= document.size() || document.at(offset) != ':') {
            return refuse(AttestationRejection::BundleMalformed, "a bundle member carries no value");
        }
        ++offset;
        while (offset < document.size() && kIsSpace(document.at(offset))) {
            ++offset;
        }

        const std::size_t kValueStart = offset;
        std::size_t depth = 0;
        bool inString = false;
        while (offset < document.size()) {
            const char kCharacter = document.at(offset);
            if (inString) {
                if (kCharacter == '\\') {
                    ++offset;
                } else if (kCharacter == '"') {
                    inString = false;
                }
                ++offset;
                continue;
            }
            if (kCharacter == '"') {
                inString = true;
                ++offset;
                continue;
            }
            if (kCharacter == '{' || kCharacter == '[') {
                ++depth;
                ++offset;
                continue;
            }
            if (kCharacter == '}' || kCharacter == ']') {
                if (depth == 0) {
                    break;
                }
                --depth;
                ++offset;
                continue;
            }
            if (kCharacter == ',' && depth == 0) {
                break;
            }
            ++offset;
        }
        if (inString || depth != 0) {
            return refuse(AttestationRejection::BundleMalformed, "a bundle member value is unterminated");
        }

        if (kKey == name) {
            std::string_view value = document.substr(kValueStart, offset - kValueStart);
            while (!value.empty() && kIsSpace(value.back())) {
                value.remove_suffix(1);
            }
            if (value.empty()) {
                return refuse(AttestationRejection::BundleMalformed,
                              "the bundle member " + std::string(name) + " carries no value");
            }
            return value;
        }
    }
    return refuse(AttestationRejection::EnvelopeMismatch, "the bundle carries no " + std::string(name) + " member");
}

// The same isolation for a member whose value must be one exact string. The
// quotes are part of the comparison, so a member holding an object or a number
// cannot compare equal to a string by accident.
AttestationResult<void>
requireTopLevelString(std::string_view document, std::string_view name, std::string_view expected) {
    auto value = extractTopLevelValue(document, name);
    if (!value) {
        return std::unexpected(value.error());
    }
    const std::string kQuoted = "\"" + std::string(expected) + "\"";
    if (*value != kQuoted) {
        return refuse(AttestationRejection::EnvelopeMismatch,
                      "the bundle " + std::string(name) + " is " + std::string(*value));
    }
    return {};
}

// An in-toto statement writes a subject digest the way the in-toto spec does:
// the algorithm is the member name and the value is bare lowercase hexadecimal.
// This repository writes a digest the way OCI does, as one `sha256:<hex>`
// string, and every other digest it compares is in that form. The two are the
// same fact in two notations, so the statement's notation is converted once,
// here, and every later comparison is between values of one shape.
//
// This is measured rather than assumed: the first genuine bundle this lane
// produced carries `"sha256": "03074dec..."` with no prefix. Comparing that
// against a locally measured `sha256:03074dec...` can never be equal, so a
// verifier that skipped this step would refuse every real attestation while
// passing a synthetic fixture that had been written in the local notation.
//
// A statement that already carries a prefix, or a value that is not exactly
// sixty-four lowercase hexadecimal characters, is refused rather than repaired.
// A digest is either exactly what it claims to be or it is not a digest.
AttestationResult<std::string> requireStatementDigest(const CanonicalValue& digests) {
    auto hex = requireString(digests, "sha256", AttestationRejection::SubjectMismatch);
    if (!hex) {
        return std::unexpected(hex.error());
    }
    constexpr std::size_t kHexLength = 64;
    const bool kIsLowercaseHex = std::ranges::all_of(*hex, [](char character) {
        return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
    });
    if (hex->size() != kHexLength || !kIsLowercaseHex) {
        return refuse(AttestationRejection::SubjectMismatch,
                      "the attested subject digest is not sixty-four lowercase hexadecimal characters: " + *hex);
    }
    return std::string(kDigestPrefix) + *hex;
}

} // namespace

AttestationResult<AttestationClaim> parseAttestationClaim(const CanonicalValue& attestation) {
    if (attestation.kind() != CanonicalValue::Kind::Object) {
        return refuse(AttestationRejection::ClaimMalformed, "attestation claim is not an object");
    }

    const CanonicalValue* bundle = attestation.find("bundle");
    if (bundle == nullptr) {
        return refuse(AttestationRejection::ClaimMalformed, "attestation claim carries no bundle descriptor");
    }
    auto parsedBundle = parseDescriptor(*bundle);
    if (!parsedBundle) {
        return refuse(AttestationRejection::ClaimMalformed,
                      "bundle descriptor is unusable: " + parsedBundle.error().detail);
    }

    AttestationClaim claim;
    claim.bundle = *std::move(parsedBundle);

    struct TextMember {
        std::string_view name;
        std::string* target;
    };
    const std::array<TextMember, 8> kTextMembers{{
        {"subjectName", &claim.subjectName},
        {"subjectDigest", &claim.subjectDigest},
        {"builderId", &claim.builderId},
        {"sourceRepository", &claim.sourceRepository},
        {"sourceCommit", &claim.sourceCommit},
        {"sourceRef", &claim.sourceRef},
        {"workflowPath", &claim.workflowPath},
        {"workflowRef", &claim.workflowRef},
    }};
    for (const auto& member : kTextMembers) {
        auto text = requireString(attestation, member.name, AttestationRejection::ClaimMalformed);
        if (!text) {
            return std::unexpected(text.error());
        }
        *member.target = *std::move(text);
    }

    struct IntegerMember {
        std::string_view name;
        std::int64_t* target;
    };
    const std::array<IntegerMember, 2> kIntegerMembers{{
        {"runId", &claim.runId},
        {"runAttempt", &claim.runAttempt},
    }};
    for (const auto& member : kIntegerMembers) {
        const CanonicalValue* value = attestation.find(member.name);
        if (value == nullptr || value->kind() != CanonicalValue::Kind::Integer || value->integer() < 0) {
            return refuse(AttestationRejection::RunIdentityMissing,
                          "run identity member is absent or negative: " + std::string(member.name));
        }
        *member.target = value->integer();
    }
    if (claim.runId == 0 || claim.runAttempt == 0) {
        return refuse(AttestationRejection::RunIdentityMissing, "run identity is present but zero");
    }
    return claim;
}

AttestationResult<DecodedProvenance> decodeProvenanceBundle(std::string_view bundleBytes) {
    if (bundleBytes.size() > kMaximumBundleBytes) {
        return refuse(AttestationRejection::BundleMalformed, "bundle exceeds the accepted ceiling");
    }
    // The bundle is external material and is not one of Rawframe's canonical
    // records, so it is parsed with the subset reader rather than ingested as a
    // canonical record. Requiring a foreign producer to emit our canonical form
    // would be requiring the wrong thing of the wrong party.
    //
    // A trailing end-of-line is part of that. The first genuine bundle this lane
    // produced ends with a newline, which a canonical record may not have, and
    // refusing it would refuse every real attestation over a byte nobody signed
    // anything about. Only what is parsed is trimmed: the descriptor is verified
    // by the caller over the exact file bytes, and the signature is verified by
    // Cosign over the exact file, so neither can be widened by this.
    while (!bundleBytes.empty() && (bundleBytes.back() == '\n' || bundleBytes.back() == '\r' ||
                                    bundleBytes.back() == ' ' || bundleBytes.back() == '\t')) {
        bundleBytes.remove_suffix(1);
    }
    if (auto status = requireTopLevelString(bundleBytes, "mediaType", kSigstoreBundleMediaType); !status) {
        return std::unexpected(status.error());
    }

    auto envelopeText = extractTopLevelValue(bundleBytes, "dsseEnvelope");
    if (!envelopeText) {
        return std::unexpected(envelopeText.error());
    }
    auto parsedEnvelope = parseCanonicalSubset(*envelopeText);
    if (!parsedEnvelope) {
        return refuse(AttestationRejection::BundleMalformed,
                      "the envelope is not parsable: " + parsedEnvelope.error().detail);
    }
    const CanonicalValue& envelope = *parsedEnvelope;

    auto payloadType = requireString(envelope, "payloadType", AttestationRejection::EnvelopeMismatch);
    if (!payloadType) {
        return std::unexpected(payloadType.error());
    }
    if (*payloadType != kInTotoPayloadType) {
        return refuse(AttestationRejection::EnvelopeMismatch, "unexpected payload type: " + *payloadType);
    }
    const CanonicalValue* signatures = envelope.find("signatures");
    if (signatures == nullptr || signatures->kind() != CanonicalValue::Kind::Array ||
        signatures->elements().size() != 1U) {
        return refuse(AttestationRejection::EnvelopeMismatch, "the envelope must carry exactly one signature");
    }

    auto encodedPayload = requireString(envelope, "payload", AttestationRejection::EnvelopeMismatch);
    if (!encodedPayload) {
        return std::unexpected(encodedPayload.error());
    }
    auto payloadBytes = decodeBase64(*encodedPayload);
    if (!payloadBytes) {
        return std::unexpected(payloadBytes.error());
    }
    auto parsedStatement = parseCanonicalSubset(*payloadBytes);
    if (!parsedStatement) {
        return refuse(AttestationRejection::StatementMismatch,
                      "statement is not parsable: " + parsedStatement.error().detail);
    }
    const CanonicalValue& statement = *parsedStatement;

    auto statementType = requireString(statement, "_type", AttestationRejection::StatementMismatch);
    if (!statementType) {
        return std::unexpected(statementType.error());
    }
    auto predicateType = requireString(statement, "predicateType", AttestationRejection::StatementMismatch);
    if (!predicateType) {
        return std::unexpected(predicateType.error());
    }
    if (*statementType != kInTotoStatementType || *predicateType != kSlsaProvenancePredicateType) {
        return refuse(AttestationRejection::StatementMismatch,
                      "statement or predicate type is not the accepted one: " + *statementType + " / " +
                          *predicateType);
    }

    const CanonicalValue* subjects = statement.find("subject");
    if (subjects == nullptr || subjects->kind() != CanonicalValue::Kind::Array || subjects->elements().size() != 1U) {
        return refuse(AttestationRejection::SubjectMismatch, "the statement must bind exactly one subject");
    }
    const CanonicalValue& subject = subjects->elements().front();
    auto subjectName = requireString(subject, "name", AttestationRejection::SubjectMismatch);
    if (!subjectName) {
        return std::unexpected(subjectName.error());
    }
    auto subjectDigests = requireObject(subject, "digest", AttestationRejection::SubjectMismatch);
    if (!subjectDigests) {
        return std::unexpected(subjectDigests.error());
    }
    auto subjectDigest = requireStatementDigest(**subjectDigests);
    if (!subjectDigest) {
        return std::unexpected(subjectDigest.error());
    }

    auto predicate = requireObject(statement, "predicate", AttestationRejection::StatementMismatch);
    if (!predicate) {
        return std::unexpected(predicate.error());
    }
    auto buildDefinition = requireObject(**predicate, "buildDefinition", AttestationRejection::StatementMismatch);
    if (!buildDefinition) {
        return std::unexpected(buildDefinition.error());
    }
    auto externalParameters =
        requireObject(**buildDefinition, "externalParameters", AttestationRejection::WorkflowMismatch);
    if (!externalParameters) {
        return std::unexpected(externalParameters.error());
    }
    auto workflow = requireObject(**externalParameters, "workflow", AttestationRejection::WorkflowMismatch);
    if (!workflow) {
        return std::unexpected(workflow.error());
    }

    DecodedProvenance decoded;
    decoded.subjectName = *std::move(subjectName);
    decoded.subjectDigest = *std::move(subjectDigest);

    auto workflowRepository = requireString(**workflow, "repository", AttestationRejection::SourceMismatch);
    auto workflowPath = requireString(**workflow, "path", AttestationRejection::WorkflowMismatch);
    auto workflowRef = requireString(**workflow, "ref", AttestationRejection::WorkflowMismatch);
    if (!workflowRepository) {
        return std::unexpected(workflowRepository.error());
    }
    if (!workflowPath) {
        return std::unexpected(workflowPath.error());
    }
    if (!workflowRef) {
        return std::unexpected(workflowRef.error());
    }
    decoded.sourceRepository = *std::move(workflowRepository);
    decoded.workflowPath = *std::move(workflowPath);
    decoded.workflowRef = *std::move(workflowRef);

    auto internalParameters =
        requireObject(**buildDefinition, "internalParameters", AttestationRejection::RunIdentityMissing);
    if (!internalParameters) {
        return std::unexpected(internalParameters.error());
    }
    auto github = requireObject(**internalParameters, "github", AttestationRejection::RunIdentityMissing);
    if (!github) {
        return std::unexpected(github.error());
    }

    // The environment that produced the run, which the certificate does not
    // distinguish. A self-hosted runner in this organization entering through
    // the protected ref receives the same issuer and the same certificate
    // identity as a hosted one, so without this the six identity checks would
    // all pass for a machine ADR-0082 does not admit as a producer.
    auto runnerEnvironment =
        requireString(**github, "runner_environment", AttestationRejection::RunnerEnvironmentUnadmitted);
    if (!runnerEnvironment) {
        return std::unexpected(runnerEnvironment.error());
    }
    if (*runnerEnvironment != kTrustedRunnerEnvironment) {
        return refuse(AttestationRejection::RunnerEnvironmentUnadmitted,
                      "the run was not produced on an admitted runner environment: " + *runnerEnvironment);
    }

    const CanonicalValue* resolved = (*buildDefinition)->find("resolvedDependencies");
    if (resolved == nullptr || resolved->kind() != CanonicalValue::Kind::Array || resolved->elements().empty()) {
        return refuse(AttestationRejection::SourceMismatch, "the statement resolves no source dependency");
    }
    const CanonicalValue& source = resolved->elements().front();
    auto sourceUri = requireString(source, "uri", AttestationRejection::SourceMismatch);
    if (!sourceUri) {
        return std::unexpected(sourceUri.error());
    }
    auto sourceDigests = requireObject(source, "digest", AttestationRejection::SourceMismatch);
    if (!sourceDigests) {
        return std::unexpected(sourceDigests.error());
    }
    auto sourceCommit = requireString(**sourceDigests, "gitCommit", AttestationRejection::SourceMismatch);
    if (!sourceCommit) {
        return std::unexpected(sourceCommit.error());
    }
    decoded.sourceCommit = *std::move(sourceCommit);

    // The resolved source URI carries the ref after an at sign. It is split
    // rather than pattern-matched so that a URI with no ref fails here instead
    // of producing an empty ref that would later compare equal to nothing.
    const std::string kUri = *std::move(sourceUri);
    const auto kSeparator = kUri.rfind('@');
    if (kSeparator == std::string::npos || kSeparator + 1U >= kUri.size()) {
        return refuse(AttestationRejection::SourceMismatch, "the resolved source URI carries no ref: " + kUri);
    }
    decoded.sourceRef = kUri.substr(kSeparator + 1U);

    auto runDetails = requireObject(**predicate, "runDetails", AttestationRejection::BuilderMismatch);
    if (!runDetails) {
        return std::unexpected(runDetails.error());
    }
    auto builder = requireObject(**runDetails, "builder", AttestationRejection::BuilderMismatch);
    if (!builder) {
        return std::unexpected(builder.error());
    }
    auto builderId = requireString(**builder, "id", AttestationRejection::BuilderMismatch);
    if (!builderId) {
        return std::unexpected(builderId.error());
    }
    decoded.builderId = *std::move(builderId);

    auto metadata = requireObject(**runDetails, "metadata", AttestationRejection::RunIdentityMissing);
    if (!metadata) {
        return std::unexpected(metadata.error());
    }
    auto invocationId = requireString(**metadata, "invocationId", AttestationRejection::RunIdentityMissing);
    if (!invocationId) {
        return std::unexpected(invocationId.error());
    }

    // The invocation identity is the URL of one execution, and it is the one
    // thing in the statement that names a single execution rather than a
    // workflow. Its shape is `.../actions/runs/<run>/attempts/<attempt>`, and
    // both markers are required: without them a URL that merely ends in two
    // numbers would be read as a run identity it never claimed to be.
    constexpr std::string_view kRunsMarker = "/actions/runs/";
    constexpr std::string_view kAttemptsMarker = "/attempts/";
    const std::string kInvocation = *std::move(invocationId);
    const auto kRunsOffset = kInvocation.rfind(kRunsMarker);
    const auto kAttemptsOffset = kInvocation.rfind(kAttemptsMarker);
    if (kRunsOffset == std::string::npos || kAttemptsOffset == std::string::npos ||
        kAttemptsOffset <= kRunsOffset + kRunsMarker.size()) {
        return refuse(AttestationRejection::RunIdentityMissing,
                      "invocation identity is not a run attempt URL: " + kInvocation);
    }
    const std::string kRunText =
        kInvocation.substr(kRunsOffset + kRunsMarker.size(), kAttemptsOffset - kRunsOffset - kRunsMarker.size());
    const std::string kAttemptText = kInvocation.substr(kAttemptsOffset + kAttemptsMarker.size());

    const auto kParsePositive = [](std::string_view text, std::int64_t& target) {
        if (text.empty() || text.size() > 18U) {
            return false;
        }
        std::int64_t accumulated = 0;
        for (const char kCharacter : text) {
            if (kCharacter < '0' || kCharacter > '9') {
                return false;
            }
            accumulated = (accumulated * 10) + (kCharacter - '0');
        }
        if (accumulated <= 0) {
            return false;
        }
        target = accumulated;
        return true;
    };
    if (!kParsePositive(kRunText, decoded.runId) || !kParsePositive(kAttemptText, decoded.runAttempt)) {
        return refuse(AttestationRejection::RunIdentityMissing,
                      "invocation identity does not name a positive run and attempt: " + kInvocation);
    }
    return decoded;
}

AttestationResult<std::string> digestSubject(const std::filesystem::path& subjectPath) {
    auto digest = sha256File(subjectPath);
    if (!digest) {
        return refuse(AttestationRejection::BundleUnreadable, "cannot digest the subject: " + digest.error().message);
    }
    return std::string(kDigestPrefix) + *digest;
}

AttestationResult<void> verifyBundleSignature(const AttestationInputs& inputs, std::string_view subjectDigest) {
    std::error_code error;
    if (!std::filesystem::is_regular_file(inputs.cosign, error) || error) {
        return refuse(AttestationRejection::VerifierUnavailable,
                      "the locked verifier is absent at " + inputs.cosign.string());
    }
    if (!std::filesystem::is_regular_file(inputs.trustedRoot, error) || error) {
        return refuse(AttestationRejection::VerifierUnavailable,
                      "the pinned trusted root is absent at " + inputs.trustedRoot.string());
    }

    // The digest is passed without its algorithm prefix because the verifier
    // takes the algorithm separately. Both are stated rather than inferred.
    std::string bareDigest(subjectDigest);
    if (bareDigest.starts_with(kDigestPrefix)) {
        bareDigest.erase(0, kDigestPrefix.size());
    }

    ProcessRequest request;
    request.executable = inputs.cosign;
    // A directory the child is certain to have, and one whose identity the lane
    // already proved. Every path handed to the verifier is absolute, so this
    // decides nothing about what is verified; it exists because a process needs
    // somewhere to start. Leaving it empty was not neutral: Windows refuses to
    // create the process at all, and POSIX would have changed to no directory
    // and run somewhere unstated, so the verifier could not run on either host.
    request.workingDirectory = inputs.cosign.parent_path();
    request.arguments = {
        "verify-blob-attestation",
        "--bundle",
        inputs.bundlePath.string(),
        "--trusted-root",
        inputs.trustedRoot.string(),
        "--digest",
        bareDigest,
        "--digestAlg",
        "sha256",
        "--type",
        "slsaprovenance1",
        "--certificate-identity",
        std::string(kTrustedCertificateIdentity),
        "--certificate-oidc-issuer",
        std::string(kTrustedCertificateIssuer),
    };
    request.timeout = kVerifierTimeout;

    auto result = runBoundedProcess(request);
    if (!result) {
        return refuse(AttestationRejection::VerifierUnavailable,
                      "the verifier could not be run: " + result.error().message);
    }
    if (result->exitCode != 0) {
        return refuse(AttestationRejection::SignatureInvalid,
                      "the verifier refused the bundle: " + result->standardError);
    }
    const std::string kCombined = result->standardOutput + result->standardError;
    if (!kCombined.contains("Verified OK")) {
        return refuse(AttestationRejection::SignatureInvalid, "the verifier did not report a verified bundle");
    }
    return {};
}

AttestationResult<DecodedProvenance> verifyAttestation(const AttestationClaim& claim, const AttestationInputs& inputs) {
    auto bundleBytes = readBoundedFile(inputs.bundlePath, kMaximumBundleBytes);
    if (!bundleBytes) {
        return refuse(AttestationRejection::BundleUnreadable, "cannot read the bundle: " + bundleBytes.error().message);
    }
    const std::string_view kBundleView(bundleBytes->data(), bundleBytes->size());

    // The claim's own descriptor is checked against the bundle bytes first. A
    // record that points at a bundle it does not describe is refused before any
    // of the bundle's content is believed.
    auto descriptorStatus = verifyDescriptor(claim.bundle, kBundleView, claim.bundle.mediaType);
    if (!descriptorStatus) {
        return refuse(AttestationRejection::ClaimMalformed,
                      "the bundle descriptor does not identify the bundle: " + descriptorStatus.error().detail);
    }

    auto decoded = decodeProvenanceBundle(kBundleView);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }

    // Recomputed from the artifact, never read from the statement.
    auto measured = digestSubject(inputs.subjectPath);
    if (!measured) {
        return std::unexpected(measured.error());
    }
    if (*measured != claim.subjectDigest || *measured != decoded->subjectDigest) {
        return refuse(AttestationRejection::SubjectMismatch,
                      "the subject digest measured locally is " + *measured + " and the claim says " +
                          claim.subjectDigest);
    }
    if (decoded->subjectName != claim.subjectName) {
        return refuse(AttestationRejection::SubjectMismatch, "the attested subject name is " + decoded->subjectName);
    }

    // The statement and the claim spell the repository differently, so each is
    // held to the spelling its own format uses and the two constants carry the
    // fact that they are one repository. Comparing the two fields to each other
    // instead would be refusing a claim for being what its schema requires.
    if (decoded->sourceRepository != kTrustedSourceRepositoryUri || decoded->sourceRef != kTrustedProtectedRef ||
        claim.sourceRepository != kTrustedSourceRepositoryPath || claim.sourceCommit != decoded->sourceCommit ||
        claim.sourceRef != decoded->sourceRef) {
        return refuse(AttestationRejection::SourceMismatch,
                      "the attested source is " + decoded->sourceRepository + "@" + decoded->sourceRef);
    }
    if (decoded->workflowPath != kTrustedEntryWorkflowPath || decoded->workflowRef != kTrustedProtectedRef ||
        claim.workflowPath != decoded->workflowPath || claim.workflowRef != decoded->workflowRef) {
        return refuse(AttestationRejection::WorkflowMismatch,
                      "the attested workflow is " + decoded->workflowPath + "@" + decoded->workflowRef);
    }

    // The builder identity is the producer's own name, and it is anchored rather
    // than merely compared to the claim. ADR-0082 requires the protected
    // workflow's path to match, and for a reusable producer this is the field
    // that carries it: the external parameters above name the entry point, not
    // the workflow that signed.
    if (decoded->builderId != kTrustedCertificateIdentity || claim.builderId != decoded->builderId) {
        return refuse(AttestationRejection::BuilderMismatch, "the attested builder is " + decoded->builderId);
    }
    if (claim.runId != decoded->runId || claim.runAttempt != decoded->runAttempt) {
        return refuse(AttestationRejection::RunIdentityMissing, "the claimed run identity is not the attested one");
    }

    auto signatureStatus = verifyBundleSignature(inputs, *measured);
    if (!signatureStatus) {
        return std::unexpected(signatureStatus.error());
    }
    return decoded;
}

} // namespace rawframe::tool::evidence
