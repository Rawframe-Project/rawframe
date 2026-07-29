# Windows container host for the ADR-0082 trusted verification lane.
#
# ADR-0083 makes a container host's operating-system identity its image digest,
# which is why the base is referenced by digest and never by tag. The `ltsc2025`
# tag is republished every servicing month; this image has to name exactly one
# set of bytes, and a rebuild onto a newer base is a new digest and a reviewed
# new host identity rather than a silent update.
#
# Server Core is the base because the locked tuple needs a real Windows SDK
# registration, a real Visual Studio instance record, and the inbox SignTool and
# curl, none of which exist in Nano Server.
ARG RF_WINDOWS_BASE_DIGEST=sha256:d5bbb83057f6bc2b6aeba5d01ec80a53003aba9bc84a6b1ebe780570cd52558a
FROM mcr.microsoft.com/windows/servercore@${RF_WINDOWS_BASE_DIGEST}

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# The installer proves every locked identity itself and fails the build when one
# of them is absent, so an image that does not match the tuple never exists.
COPY install-build-tools.ps1 C:\\rf\\install-build-tools.ps1
RUN C:\rf\install-build-tools.ps1; Remove-Item -Force C:\rf\install-build-tools.ps1

# States which host class the probe is running under. It says what this image is,
# never that it may be trusted: a hand-built image can carry the same file, and
# it would still produce `diagnostic_untrusted` evidence, because trust comes
# from the ADR-0082 attestation over the protected workflow and from nothing
# else. The digest that makes this image an identity is enforced by whoever
# starts the container, which is the only place it can be known.
COPY host-identity.json C:\\rf\\host-identity.json

LABEL org.rawframe.host-class="container" \
      org.rawframe.host-id="host.container_windows_servercore_ltsc2025_x86_64" \
      org.rawframe.authority="ADR-0083"
