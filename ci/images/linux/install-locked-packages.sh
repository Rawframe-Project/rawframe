#!/bin/sh
# Installs exactly the packages the locked Linux host tuple names, at exactly
# their locked versions, and proves each one byte for byte before it is used.
#
# Each input line is `package|version|filename|size|sha256`, which is the exact
# shape `RF_LINUX_HOST_PACKAGES` uses in the authority file.
#
# The work is done in two passes on purpose, because they answer two different
# questions.
#
# The first pass downloads each locked package at its exact pinned version and
# compares the bytes to the locked size and SHA-256. `apt-get download` is
# admitted on the same basis as `dpkg-query` in `cmake/sync/linux_host.cmake`:
# a named non-interpreting utility asked for one exact version, producing bytes
# that are compared and never trusted. This pass proves the repository's own
# recorded identity for the tuple.
#
# The second pass installs those exact versions through the resolver, so that
# their own dependencies come with them. The tuple names the packages the host
# is identified by, not the closure they need to work: `perl` needs
# `perl-modules-5.38` and `libperl5.38t64`, and `libxml2` needs `libicu74`, none
# of which are locked because none of them identifies the host. An earlier
# revision of this script installed the tuple alone with `--force-depends` and
# produced an image with three broken packages, which is worse than useless: it
# is an environment that looks locked and cannot run what it locks.
set -eu

list="$1"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

export DEBIAN_FRONTEND=noninteractive

# The locked tuple was captured from the `noble` release pocket, so the image
# reads that pocket and nothing else. This is not a convenience: with the update
# pockets enabled, a locked package and its unlocked dependency resolve from
# different pockets and contradict each other. `perl 5.38.2-3.2build2` requires
# `libperl5.38t64` at exactly its own version, the update pocket offers
# `5.38.2-3.2ubuntu0.3`, and the resolver correctly refuses to satisfy both.
# Narrowing the pocket makes the whole dependency closure consistent by
# construction rather than by pinning each dependency individually.
#
# The keyring is the one the base image already ships, so package signatures are
# still checked by Canonical's archive key. Only the suite selection changes.
#
# An unpatched pocket is the intended state here, not an oversight. ADR-0083
# makes this image's identity its digest, and a security update is a new base
# image, a new digest, and a reviewed host identity, never an in-place upgrade.
cat > /etc/apt/sources.list.d/ubuntu.sources <<'SOURCES'
Types: deb
URIs: http://archive.ubuntu.com/ubuntu/
Suites: noble
Components: main universe restricted multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
SOURCES

apt-get update -qq

# Pass one: prove the bytes.
verified=0
cd "$work"
while IFS='|' read -r package version filename size digest; do
    [ -n "$package" ] || continue

    rm -f ./*.deb
    apt-get download -qq "$package=$version"
    deb="$(ls -1 ./*.deb | head -n 1)"

    actual_size="$(stat -c %s "$deb")"
    if [ "$actual_size" != "$size" ]; then
        echo "rf: $package byte size is $actual_size and the lock says $size" >&2
        exit 1
    fi
    actual_digest="$(sha256sum "$deb" | cut -d' ' -f1)"
    if [ "$actual_digest" != "$digest" ]; then
        echo "rf: $package digest is $actual_digest and the lock says $digest" >&2
        exit 1
    fi
    verified=$((verified + 1))
done < "$list"
rm -f ./*.deb
echo "rf: verified $verified locked packages against the lock"

# Pass two: install those exact versions, with their dependencies.
pins=""
while IFS='|' read -r package version filename size digest; do
    [ -n "$package" ] || continue
    pins="$pins $package=$version"
done < "$list"

# shellcheck disable=SC2086
apt-get install -y --no-install-recommends --allow-downgrades $pins

# The bootstrap transport is a separate authority from the host tuple.
# `third_party/toolchain.lock.json` requires `/usr/bin/curl` at 8.5.0 or later
# and records the identity as "Ubuntu 24.04 inbox curl 8.5.0-2ubuntu10", which
# is the release-pocket version this image already resolves to. It is installed
# here rather than added to the locked tuple because the tuple states what
# identifies the host, and the transport has its own record that states what
# admits it.
apt-get install -y --no-install-recommends curl ca-certificates

apt-get clean
rm -rf /var/lib/apt/lists/*

# The image is only correct if every locked version is the installed version,
# and if nothing is left half configured. Checking here means a broken image
# fails at build time rather than in the middle of a verification run that was
# supposed to be proving something else.
status=0
while IFS='|' read -r package version filename size digest; do
    [ -n "$package" ] || continue
    installed="$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true)"
    if [ "$installed" != "$version" ]; then
        echo "rf: $package is $installed after install and the lock says $version" >&2
        status=1
    fi
done < "$list"

# The transport record names one exact package identity, so it is checked here
# for the same reason the tuple is: a silent substitution would only be found
# later, inside a run that was supposed to be proving something else.
transport_version="$(dpkg-query -W -f='${Version}' curl 2>/dev/null || true)"
if [ "$transport_version" != "8.5.0-2ubuntu10" ]; then
    echo "rf: curl is $transport_version and the transport record says 8.5.0-2ubuntu10" >&2
    status=1
fi

broken="$(dpkg-query -W -f='${Package} ${Status}\n' | grep -v ' install ok installed$' || true)"
if [ -n "$broken" ]; then
    echo "rf: packages are not fully installed:" >&2
    echo "$broken" >&2
    status=1
fi

exit "$status"
