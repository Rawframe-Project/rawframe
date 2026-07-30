#!/bin/sh
# Stages the one admitted bootstrap CMake identity outside any repository tree.
#
# Stage 0 admits exactly one CMake, the locked 4.4.0 artifact, and refuses to run
# its publishing stages through a CMake living beneath `out/prepared` (`RF1323`).
# A workstation satisfies that by pre-staging the locked archive next to the
# checkout; a container host has no developer to do it, so the image carries it
# at a fixed path that no checkout can reach.
#
# The values below are the `tool.cmake.linux_x86_64` record in
# `third_party/artifacts.lock.json`, repeated here because this script runs
# before any checkout exists to read them from. They are checked, not trusted:
# a mismatch fails the image build.
#
# The archive's OpenPGP signature is not checked here, and that is deliberate
# rather than skipped. The signature answers who produced these bytes, and it was
# answered once when the lock recorded them; the sync stage answers it again on
# every run against the same record, through the release key and the signed
# checksum file. What this script needs is the narrower guarantee that the bytes
# it stages are the bytes the lock names, which is exactly what a digest proves.
set -eu

version="4.4.0"
archive_uri="https://github.com/Kitware/CMake/releases/download/v${version}/cmake-${version}-linux-x86_64.tar.gz"
archive_bytes="64838835"
archive_digest="3864eb649b4466ae126a64bbde1657adad78efbbaa068bf38201de5cf1b5349f"

stage_root="/opt/rf/bootstrap"
archive_root="cmake-${version}-linux-x86_64"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
archive="${work}/cmake.tar.gz"

echo "rf: acquiring the locked bootstrap CMake ${version}"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --output "$archive" "$archive_uri"

actual_bytes="$(stat -c %s "$archive")"
if [ "$actual_bytes" != "$archive_bytes" ]; then
    echo "rf: the CMake archive is $actual_bytes bytes and the lock says $archive_bytes" >&2
    exit 1
fi
actual_digest="$(sha256sum "$archive" | cut -d' ' -f1)"
if [ "$actual_digest" != "$archive_digest" ]; then
    echo "rf: the CMake archive digest is $actual_digest and the lock says $archive_digest" >&2
    exit 1
fi

mkdir -p "$stage_root"
tar --extract --file "$archive" --directory "$stage_root"

cmake_executable="${stage_root}/${archive_root}/bin/cmake"
if [ ! -x "$cmake_executable" ]; then
    echo "rf: the extracted archive has no executable at $cmake_executable" >&2
    exit 1
fi

# The version is proved from the staged executable rather than assumed from the
# archive name, because the name is the part an attacker controls for free.
reported="$("$cmake_executable" --version | head -n 1)"
if [ "$reported" != "cmake version ${version}" ]; then
    echo "rf: the staged CMake reports '$reported' and the lock says version ${version}" >&2
    exit 1
fi

echo "rf: the bootstrap CMake is staged at $cmake_executable"
