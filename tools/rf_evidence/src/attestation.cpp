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
            table[static_cast<unsigned char>(kAlphabet[index])] = static_cast<std::int8_t>(index);
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
            const char character = encoded[offset + index];
            if (character == '=') {
                // Padding is only ever the last one or two characters of the
                // last quantum. Anywhere else it is a second encoding of the
                // same bytes, which is exactly what canonical form forbids.
                if (offset + 4U != encoded.size() || index < 2U) {
                    return refuse(AttestationRejection::BundleMalformed, "payload padding is misplaced");
                }
                ++padding;
                quantum[index] = 0;
                continue;
            }
            if (padding != 0) {
                return refuse(AttestationRejection::BundleMalformed, "payload has data after padding");
            }
            const std::int8_t value = kReverse[static_cast<unsigned char>(character)];
            if (value < 0) {
                return refuse(AttestationRejection::BundleMalformed, "payload carries a character outside base64");
            }
            quantum[index] = value;
        }
        const auto triple = static_cast<std::uint32_t>((static_cast<std::uint32_t>(quantum[0]) << 18U)
                                                       | (static_cast<std::uint32_t>(quantum[1]) << 12U)
                                                       | (static_cast<std::uint32_t>(quantum[2]) << 6U)
                                                       | static_cast<std::uint32_t>(quantum[3]));
        decoded.push_back(static_cast<char>((triple >> 16U) & 0xFFU));
        if (padding < 2U) {
            decoded.push_back(static_cast<char>((triple >> 8U) & 0xFFU));
        }
        if (padding < 1U) {
            decoded.push_back(static_cast<char>(triple & 0xFFU));
        }
    }
    return decoded;
}

AttestationResult<std::string> requireString(const CanonicalValue& parent, std::string_view name,
                                             AttestationRejection rejection) {
    const CanonicalValue* member = parent.find(name);
    if (member == nullptr || member->kind() != CanonicalValue::Kind::String) {
        return refuse(rejection, "missing string member: " + std::string(name));
    }
    return member->text();
}

AttestationResult<const CanonicalValue*> requireObject(const CanonicalValue& parent, std::string_view name,
                                                       AttestationRejection rejection) {
    const CanonicalValue* member = parent.find(name);
    if (member == nullptr || member->kind() != CanonicalValue::Kind::Object) {
        return refuse(rejection, "missing object member: " + std::string(name));
    }
    return member;
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
        return refuse(AttestationRejection::ClaimMalformed, "bundle descriptor is unusable: " + parsedBundle.error().detail);
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
    auto parsedBundle = parseCanonicalSubset(bundleBytes);
    if (!parsedBundle) {
        return refuse(AttestationRejection::BundleMalformed, "bundle is not parsable: " + parsedBundle.error().detail);
    }
    const CanonicalValue& bundle = *parsedBundle;

    auto mediaType = requireString(bundle, "mediaType", AttestationRejection::EnvelopeMismatch);
    if (!mediaType) {
        return std::unexpected(mediaType.error());
    }
    if (*mediaType != kSigstoreBundleMediaType) {
        return refuse(AttestationRejection::EnvelopeMismatch, "unexpected bundle media type: " + *mediaType);
    }

    auto envelope = requireObject(bundle, "dsseEnvelope", AttestationRejection::EnvelopeMismatch);
    if (!envelope) {
        return std::unexpected(envelope.error());
    }
    auto payloadType = requireString(**envelope, "payloadType", AttestationRejection::EnvelopeMismatch);
    if (!payloadType) {
        return std::unexpected(payloadType.error());
    }
    if (*payloadType != kInTotoPayloadType) {
        return refuse(AttestationRejection::EnvelopeMismatch, "unexpected payload type: " + *payloadType);
    }
    const CanonicalValue* signatures = (*envelope)->find("signatures");
    if (signatures == nullptr || signatures->kind() != CanonicalValue::Kind::Array
        || signatures->elements().size() != 1U) {
        return refuse(AttestationRejection::EnvelopeMismatch, "the envelope must carry exactly one signature");
    }

    auto encodedPayload = requireString(**envelope, "payload", AttestationRejection::EnvelopeMismatch);
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
                      "statement or predicate type is not the accepted one: " + *statementType + " / " + *predicateType);
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
    auto subjectDigest = requireString(**subjectDigests, "sha256", AttestationRejection::SubjectMismatch);
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
    const std::string uri = *std::move(sourceUri);
    const auto separator = uri.rfind('@');
    if (separator == std::string::npos || separator + 1U >= uri.size()) {
        return refuse(AttestationRejection::SourceMismatch, "the resolved source URI carries no ref: " + uri);
    }
    decoded.sourceRef = uri.substr(separator + 1U);

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
    const std::string invocation = *std::move(invocationId);
    const auto runsOffset = invocation.rfind(kRunsMarker);
    const auto attemptsOffset = invocation.rfind(kAttemptsMarker);
    if (runsOffset == std::string::npos || attemptsOffset == std::string::npos
        || attemptsOffset <= runsOffset + kRunsMarker.size()) {
        return refuse(AttestationRejection::RunIdentityMissing,
                      "invocation identity is not a run attempt URL: " + invocation);
    }
    const std::string runText =
        invocation.substr(runsOffset + kRunsMarker.size(), attemptsOffset - runsOffset - kRunsMarker.size());
    const std::string attemptText = invocation.substr(attemptsOffset + kAttemptsMarker.size());

    const auto parsePositive = [](std::string_view text, std::int64_t& target) {
        if (text.empty() || text.size() > 18U) {
            return false;
        }
        std::int64_t accumulated = 0;
        for (const char character : text) {
            if (character < '0' || character > '9') {
                return false;
            }
            accumulated = (accumulated * 10) + (character - '0');
        }
        if (accumulated <= 0) {
            return false;
        }
        target = accumulated;
        return true;
    };
    if (!parsePositive(runText, decoded.runId) || !parsePositive(attemptText, decoded.runAttempt)) {
        return refuse(AttestationRejection::RunIdentityMissing,
                      "invocation identity does not name a positive run and attempt: " + invocation);
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
    const std::string combined = result->standardOutput + result->standardError;
    if (combined.find("Verified OK") == std::string::npos) {
        return refuse(AttestationRejection::SignatureInvalid, "the verifier did not report a verified bundle");
    }
    return {};
}

AttestationResult<DecodedProvenance> verifyAttestation(const AttestationClaim& claim,
                                                       const AttestationInputs& inputs) {
    auto bundleBytes = readBoundedFile(inputs.bundlePath, kMaximumBundleBytes);
    if (!bundleBytes) {
        return refuse(AttestationRejection::BundleUnreadable,
                      "cannot read the bundle: " + bundleBytes.error().message);
    }
    const std::string_view bundleView(bundleBytes->data(), bundleBytes->size());

    // The claim's own descriptor is checked against the bundle bytes first. A
    // record that points at a bundle it does not describe is refused before any
    // of the bundle's content is believed.
    auto descriptorStatus = verifyDescriptor(claim.bundle, bundleView, claim.bundle.mediaType);
    if (!descriptorStatus) {
        return refuse(AttestationRejection::ClaimMalformed,
                      "the bundle descriptor does not identify the bundle: " + descriptorStatus.error().detail);
    }

    auto decoded = decodeProvenanceBundle(bundleView);
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
                      "the subject digest measured locally is " + *measured + " and the claim says "
                          + claim.subjectDigest);
    }
    if (decoded->subjectName != claim.subjectName) {
        return refuse(AttestationRejection::SubjectMismatch, "the attested subject name is " + decoded->subjectName);
    }

    if (decoded->sourceRepository != kTrustedSourceRepository || claim.sourceRepository != decoded->sourceRepository
        || claim.sourceCommit != decoded->sourceCommit || claim.sourceRef != decoded->sourceRef) {
        return refuse(AttestationRejection::SourceMismatch,
                      "the attested source is " + decoded->sourceRepository + "@" + decoded->sourceRef);
    }
    if (decoded->workflowPath != kTrustedWorkflowPath || claim.workflowPath != decoded->workflowPath
        || claim.workflowRef != decoded->workflowRef) {
        return refuse(AttestationRejection::WorkflowMismatch,
                      "the attested workflow is " + decoded->workflowPath + "@" + decoded->workflowRef);
    }
    if (claim.builderId != decoded->builderId) {
        return refuse(AttestationRejection::BuilderMismatch, "the attested builder is " + decoded->builderId);
    }
    if (claim.runId != decoded->runId || claim.runAttempt != decoded->runAttempt) {
        return refuse(AttestationRejection::RunIdentityMissing,
                      "the claimed run identity is not the attested one");
    }

    auto signatureStatus = verifyBundleSignature(inputs, *measured);
    if (!signatureStatus) {
        return std::unexpected(signatureStatus.error());
    }
    return decoded;
}

} // namespace rawframe::tool::evidence
