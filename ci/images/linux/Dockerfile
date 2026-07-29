# Linux container host for the ADR-0082 trusted verification lane.
#
# ADR-0083 makes a container host's operating-system identity its image digest.
# That is why the base is referenced by digest and never by tag: a tag names
# whatever was published most recently, and this image has to name exactly one
# set of bytes.
#
# The base was chosen because it already carries the locked `noble` package
# versions rather than the patched ones. The current `ubuntu:24.04` tag carries
# `libc6 2.39-0ubuntu8.7` where the lock says `2.39-0ubuntu8`, so building on it
# would mean downgrading five packages that the release image already has right.
ARG RF_LINUX_BASE_DIGEST=sha256:562456a05a0dbd62a671c1854868862a4687bf979a96d48ae8e766642cd911e8
FROM ubuntu@${RF_LINUX_BASE_DIGEST}

# The package list is extracted from `cmake/sync/linux_host.cmake`, which is the
# single authority for it. It is never restated here: a second copy of the list
# is a second authority, and the two would drift.
COPY locked-packages.txt /rf/locked-packages.txt
COPY install-locked-packages.sh /rf/install-locked-packages.sh

# Invoked through the interpreter rather than as an executable, so the image does
# not depend on a file mode surviving a checkout on a filesystem that has no
# concept of one.
RUN sh /rf/install-locked-packages.sh /rf/locked-packages.txt && rm -rf /rf/install-locked-packages.sh

# States which host class the probe is running under. It says what this image is,
# never that it may be trusted: a hand-built image can carry the same file, and
# it would still produce `diagnostic_untrusted` evidence, because trust comes
# from the ADR-0082 attestation over the protected workflow and from nothing
# else. The digest that makes this image an identity is enforced by whoever
# starts the container, which is the only place it can be known.
COPY host-identity.json /rf/host-identity.json

# Recorded so a running container can state which authority it was built from
# without the build system having to remember.
LABEL org.rawframe.host-class="container" \
      org.rawframe.host-id="host.container_ubuntu_24_04_x86_64" \
      org.rawframe.authority="ADR-0083"
