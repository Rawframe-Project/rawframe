# Stages the one admitted bootstrap CMake identity outside any repository tree.
#
# Stage 0 admits exactly one CMake, the locked 4.4.0 artifact, and refuses to run
# its publishing stages through a CMake living beneath `out/prepared` (`RF1323`).
# A workstation satisfies that by pre-staging the locked archive next to the
# checkout; a container host has no developer to do it, so the image carries it
# at a fixed path that no checkout can reach.
#
# The values below are the `tool.cmake.windows_x86_64` record in
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

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$version = '4.4.0'
$archiveUri = "https://github.com/Kitware/CMake/releases/download/v$version/cmake-$version-windows-x86_64.zip"
$archiveBytes = 54388920
$archiveSha256 = '156D70EB7625A7B469444DF7D0861D2AF8D5D0A437FCE32C350372B08F5620E8'

$stageRoot = 'C:\rf\bootstrap'
$archiveRoot = "cmake-$version-windows-x86_64"

New-Item -ItemType Directory -Force -Path 'C:\rf\work' | Out-Null
$archive = 'C:\rf\work\cmake.zip'

Write-Host "rf: acquiring the locked bootstrap CMake $version"
Invoke-WebRequest -Uri $archiveUri -OutFile $archive -UseBasicParsing

$actualBytes = (Get-Item -LiteralPath $archive).Length
if ($actualBytes -ne $archiveBytes) {
    throw "rf: the CMake archive is $actualBytes bytes and the lock says $archiveBytes"
}
$actualDigest = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if ($actualDigest -ne $archiveSha256) {
    throw "rf: the CMake archive digest is $actualDigest and the lock says $archiveSha256"
}

New-Item -ItemType Directory -Force -Path $stageRoot | Out-Null
Expand-Archive -LiteralPath $archive -DestinationPath $stageRoot -Force

$cmakeExecutable = "$stageRoot\$archiveRoot\bin\cmake.exe"
if (-not (Test-Path -LiteralPath $cmakeExecutable -PathType Leaf)) {
    throw "rf: the extracted archive has no executable at $cmakeExecutable"
}

# The version is proved from the staged executable rather than assumed from the
# archive name, because the name is the part an attacker controls for free.
$reported = (& $cmakeExecutable --version | Select-Object -First 1)
if ($reported -ne "cmake version $version") {
    throw "rf: the staged CMake reports '$reported' and the lock says version $version"
}

Remove-Item -Recurse -Force 'C:\rf\work'
Write-Host "rf: the bootstrap CMake is staged at $cmakeExecutable"
