#pragma once

#include "canonical_json.h"

#include <cstdint>
#include <filesystem>
#include <string_view>

namespace rawframe::tool::evidence {

// The schema every evidence record references for its shared definitions. It is
// an import rather than a record, so it belongs with the gate that resolves it
// and not with any one record kind.
inline constexpr std::string_view kEvidenceCommonSchemaPath = "schemas/evidence-common-v1.schema.json";

// The checks that apply to an evidence record because it is an evidence record,
// independent of which kind it is. They lived with the RawRunReceipt while it
// was the only kind; a second kind needing all three is what makes them
// generic rather than shared by coincidence.
//
// Order matters and is fixed by SPEC-0017: authority, then kind, then schema,
// then generation. Each record kind composes them; none of them reaches into
// another record's semantics.

// No member name anywhere in a record may claim an outcome. The schemas already
// close every object, so this cannot fire against an accepted schema; it exists
// so that widening a schema by accident cannot quietly open the door this rule
// closes.
[[nodiscard]] RecordStatus checkProducerAuthority(const CanonicalValue& record);

// The kind is read from the record's own bytes and compared against what the
// caller was asked to produce. A caller never supplies the kind, so a record
// cannot be relabelled by the command line that reads it.
[[nodiscard]] RecordResult<std::string> readRecordKind(const CanonicalValue& record);
[[nodiscard]] RecordStatus checkRecordKind(const CanonicalValue& record, std::string_view expectedKind);

// The generation recorded in the bytes and the generation named by the media
// type must agree, and both must equal the generation this tool implements.
// Neither of the first two is preferred over the other, because a preference
// order is how one of two cross-checks becomes decorative.
[[nodiscard]] RecordStatus
checkGenerationMatches(const CanonicalValue& record, std::string_view mediaType, std::int64_t expectedGeneration);

// Generic Draft 2020-12 validation through the pinned offline oracle, against
// the schema the calling record kind names. The instance is passed by path
// because the oracle reads files, and the canonical bytes of a record carry the
// same semantics as the authored bytes they came from, so validating either
// proves the same thing. The shared definitions schema is always handed over as
// an import, because a reference resolves against its own absolute identifier
// rather than against a sibling file on disk.
[[nodiscard]] RecordStatus validateAgainstSchema(const std::filesystem::path& repositoryRoot,
                                                 std::string_view schemaRelativePath,
                                                 const std::filesystem::path& instancePath);

} // namespace rawframe::tool::evidence
