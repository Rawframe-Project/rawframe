#!/usr/bin/env bash
# Builds the Linux container host for the ADR-0082 trusted lane.
#
# The package list has exactly one authority, `RF_LINUX_HOST_PACKAGES` in
# `cmake/sync/linux_host.cmake`. This script extracts it rather than restating
# it, and writes the extract beneath `out/`, where generated material belongs.
# A second maintained copy of that list would be a second authority, and the
# whole point of the locked tuple is that there is one.
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
authority="${repository_root}/cmake/sync/linux_host.cmake"
staging="${repository_root}/out/ci/linux-image"
context="${repository_root}/ci/images/linux"

if [[ ! -f "${authority}" ]]; then
    echo "rf: the locked Linux host authority is missing at ${authority}" >&2
    exit 1
fi

mkdir -p "${staging}"

# Reads the quoted entries of the RF_LINUX_HOST_PACKAGES block and nothing else.
# Anchoring on the set() call rather than on the shape of a line means a comment
# that happens to contain a pipe cannot be mistaken for an entry.
python3 - "${authority}" "${staging}/locked-packages.txt" <<'PY'
import re
import sys

source = open(sys.argv[1], encoding="utf-8").read()
match = re.search(r"set\(RF_LINUX_HOST_PACKAGES\s*(.*?)\n\)", source, re.S)
if match is None:
    sys.exit("rf: RF_LINUX_HOST_PACKAGES was not found in the authority file")

entries = re.findall(r'"([^"]+)"', match.group(1))
if not entries:
    sys.exit("rf: RF_LINUX_HOST_PACKAGES is empty")

for entry in entries:
    if entry.count("|") != 4:
        sys.exit(f"rf: entry is not package|version|filename|size|sha256: {entry}")

with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as handle:
    handle.write("\n".join(entries) + "\n")

print(f"rf: extracted {len(entries)} locked packages")
PY

# The three OpenPGP verifier packages Stage 0 downloads and verifies for itself.
# They are installed into the image as well, because Stage 0 extracts those exact
# debs and then runs them, and an extracted binary needs its runtime closure to
# exist. The authority is the artifact lock, so the versions and digests are read
# from it rather than restated.
python3 - "${repository_root}/third_party/artifacts.lock.json" "${staging}/verifier-packages.txt" <<'PY'
import json
import sys

wanted = ("tool.gnupg.linux_x86_64", "tool.gnupg.linux_x86_64_full", "tool.gnupg.linux_x86_64_config")
lock = json.load(open(sys.argv[1], encoding="utf-8"))
records = {entry["id"]: entry for entry in lock["artifacts"]}

lines = []
for identifier in wanted:
    record = records.get(identifier)
    if record is None:
        sys.exit(f"rf: the artifact lock has no {identifier}")
    filename = record["origins"][0].rsplit("/", 1)[1]
    package = filename.split("_", 1)[0]
    lines.append(f'{package}|{record["version"]}|{filename}|{record["byteSize"]}|{record["sha256"]}')

with open(sys.argv[2], "w", encoding="utf-8", newline="\n") as handle:
    handle.write("\n".join(lines) + "\n")

print(f"rf: extracted {len(lines)} locked verifier packages")
PY

cp "${staging}/locked-packages.txt" "${context}/locked-packages.txt"
cp "${staging}/verifier-packages.txt" "${context}/verifier-packages.txt"
trap 'rm -f "${context}/locked-packages.txt" "${context}/verifier-packages.txt"' EXIT

for required in Dockerfile install-locked-packages.sh install-bootstrap-cmake.sh host-identity.json \
                locked-packages.txt verifier-packages.txt; do
    if [[ ! -f "${context}/${required}" ]]; then
        echo "rf: the Linux image definition is missing ${required}" >&2
        exit 1
    fi
done

tag="${1:-rawframe/ci-linux:local}"
# Provenance and SBOM attestations turn the result into a manifest list whose
# entries the Windows lane cannot produce. The host identity is the image digest,
# so both lanes have to be able to name the same kind of object.
docker build --provenance=false --sbom=false --tag "${tag}" --file "${context}/Dockerfile" "${context}"

echo "rf: built ${tag}"
