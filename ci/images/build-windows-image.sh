#!/usr/bin/env bash
# Builds the Windows container host for the ADR-0082 trusted verification lane.
#
# Unlike the Linux lane there is nothing to extract from an authority file here:
# the locked Windows identities are versions and digests rather than a package
# list, and the installer script carries them where it can also prove them. This
# script exists so both lanes have the same entry point.
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
context="${repository_root}/ci/images/windows"

for required in Dockerfile install-build-tools.ps1 host-identity.json; do
    if [[ ! -f "${context}/${required}" ]]; then
        echo "rf: the Windows image definition is missing ${required}" >&2
        exit 1
    fi
done

tag="${1:-rawframe/ci-windows:local}"
docker build --tag "${tag}" --file "${context}/Dockerfile" "${context}"

echo "rf: built ${tag}"
