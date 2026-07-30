# Installs exactly the Visual Studio Build Tools and Windows SDK identities the
# locked Windows host tuple names, and proves every one of them before the image
# is allowed to exist.
#
# The bootstrapper is the fixed-version one Microsoft publishes for Build Tools.
# That property is the reason the Build Tools root is one of the two admitted
# Visual Studio instances at all: an evergreen bootstrapper installs whatever is
# current, which cannot produce a locked identity twice.
#
# Everything the tuple names is checked after the install rather than assumed
# from the component identifiers. A component identifier is a request; the
# recorded version, toolset, compiler, linker, SDK, and SignTool identities are
# the contract, and an image that misses any of them must fail here rather than
# in the middle of a verification run that was supposed to be proving something
# else.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$bootstrapperUri = 'https://download.visualstudio.microsoft.com/download/pr/4037ccca-d103-412b-a678-bc0aa164315e/07b09afd416dc05c781f171c881c23e42907eeb8d812fa1d2993dffb9323c869/vs_BuildTools.exe'
$bootstrapperBytes = 5693576
$bootstrapperSha256 = '07B09AFD416DC05C781F171C881C23E42907EEB8D812FA1D2993DFFB9323C869'

$installRoot = 'C:\Program Files\Microsoft Visual Studio\18\BuildTools'
$expectedVsVersion = '18.7.11925.98'
$expectedToolset = '14.51.36231'
$expectedClVersion = '19.51.36248'
$expectedNmakeVersion = '14.51.36248.0'

$sdkRoot = 'C:\Program Files (x86)\Windows Kits\10'
$expectedSdkGeneration = '10.0.26100.0'
$expectedSdkProductVersion = '10.0.26100'
$expectedSdkPackageVersion = '10.1.26100.8249'
$expectedSdkPackageGuid = '{204d0387-6d9a-48cf-bb7d-93d49ec0141c}'

$signTool = "$sdkRoot\bin\$expectedSdkGeneration\x64\signtool.exe"
$expectedSignToolBytes = 543144
$expectedSignToolSha256 = 'E7B517A6A2828AF2D1FBA3DA60AE1E322A95141BFAE192622725329630CAA2B3'

function Assert-Equal {
    param([string]$Actual, [string]$Expected, [string]$Subject)
    if ($Actual -ne $Expected) {
        throw "rf: $Subject is '$Actual' and the lock says '$Expected'"
    }
}

# Runs a native tool purely to read the banner it prints, and returns everything
# it wrote on both streams.
#
# `cl.exe` with no arguments prints its version banner to stderr and exits
# nonzero, which is correct behaviour for a compiler asked to compile nothing. It
# is not an error here, because the banner is the entire point of the call, so the
# stop-on-error preference is lifted for exactly the length of the call rather
# than for the script.
function Get-BannerOutput {
    param([string]$Path, [string[]]$Arguments = @())
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        return (& $Path @Arguments 2>&1 | Out-String)
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Assert-FileIdentity {
    param([string]$Path, [int]$Bytes, [string]$Sha256, [string]$Subject)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "rf: $Subject is missing at $Path"
    }
    $actualBytes = (Get-Item -LiteralPath $Path).Length
    if ($actualBytes -ne $Bytes) {
        throw "rf: $Subject is $actualBytes bytes and the lock says $Bytes"
    }
    $actualDigest = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actualDigest -ne $Sha256) {
        throw "rf: $Subject digest is $actualDigest and the lock says $Sha256"
    }
}

New-Item -ItemType Directory -Force -Path 'C:\rf\work' | Out-Null
$bootstrapper = 'C:\rf\work\vs_BuildTools.exe'

Write-Host 'rf: acquiring the fixed-version Build Tools bootstrapper'
Invoke-WebRequest -Uri $bootstrapperUri -OutFile $bootstrapper -UseBasicParsing

Assert-FileIdentity -Path $bootstrapper -Bytes $bootstrapperBytes -Sha256 $bootstrapperSha256 `
    -Subject 'the Build Tools bootstrapper'

# The digest above already fixes the bytes. The signature is checked as well
# because a digest proves that nobody altered what was fetched, and says nothing
# about who produced it. Both questions have to be answered, and only one of them
# is answered by a hash.
$signature = Get-AuthenticodeSignature -LiteralPath $bootstrapper
if ($signature.Status -ne 'Valid') {
    throw "rf: the bootstrapper Authenticode status is $($signature.Status)"
}
if ($signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    throw "rf: the bootstrapper signer is $($signature.SignerCertificate.Subject)"
}

Write-Host 'rf: installing Build Tools 18.7.3 at the admitted root'
# The install path is quoted here rather than handed over as one element of an
# argument array. Windows PowerShell joins an argument array with spaces and
# quotes nothing, so an unquoted `--installPath C:\Program Files\...` reaches the
# bootstrapper as `--installPath C:\Program` followed by stray tokens. The
# installer accepts that and reports success, which is the worst available
# outcome: a populated image whose toolchain is not where the tuple says it is.
$argumentLine = @(
    '--quiet', '--wait', '--norestart', '--nocache',
    '--installPath', "`"$installRoot`"",
    '--add', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
    '--add', 'Microsoft.VisualStudio.Component.Windows11SDK.26100'
) -join ' '
$process = Start-Process -FilePath $bootstrapper -ArgumentList $argumentLine -Wait -PassThru -NoNewWindow
Write-Host "rf: the Build Tools installer exited with $($process.ExitCode)"
if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
    throw "rf: the Build Tools installer exited with $($process.ExitCode)"
}

Write-Host 'rf: proving the installed Visual Studio identity'
$instanceRoot = 'C:\ProgramData\Microsoft\VisualStudio\Packages\_Instances'
$states = @(Get-ChildItem -Path $instanceRoot -Filter 'state.json' -Recurse -ErrorAction SilentlyContinue)
$matched = @()
foreach ($state in $states) {
    $content = Get-Content -LiteralPath $state.FullName -Raw | ConvertFrom-Json
    if ($content.installationPath -eq $installRoot) {
        $matched += $content
    }
}
if ($matched.Count -ne 1) {
    # The paths that were found are reported with the count. A bare count says
    # only that the expectation was missed, and the interesting question is
    # always where the install actually landed.
    foreach ($state in $states) {
        $content = Get-Content -LiteralPath $state.FullName -Raw | ConvertFrom-Json
        Write-Host "rf: found instance $($content.installationVersion) at $($content.installationPath)"
    }
    throw "rf: the image carries $($matched.Count) instances at the admitted root and must carry exactly one"
}
Assert-Equal -Actual $matched[0].installationVersion -Expected $expectedVsVersion `
    -Subject 'the Visual Studio installation version'

$toolsetFile = "$installRoot\VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt"
$defaultToolset = (Get-Content -LiteralPath $toolsetFile -Raw).Trim()
Assert-Equal -Actual $defaultToolset -Expected $expectedToolset -Subject 'the default MSVC toolset'

$toolsetRoot = "$installRoot\VC\Tools\MSVC\$expectedToolset"
if (-not (Test-Path -LiteralPath $toolsetRoot -PathType Container)) {
    throw "rf: the locked MSVC toolset tree is missing at $toolsetRoot"
}

$clOutput = Get-BannerOutput -Path "$toolsetRoot\bin\Hostx64\x64\cl.exe"
$clPattern = "C/C\+\+ Optimizing Compiler Version $([regex]::Escape($expectedClVersion))(\.0)? for x64"
if ($clOutput -notmatch $clPattern) {
    throw "rf: cl.exe identity differs from the locked tuple"
}

$nmakeOutput = Get-BannerOutput -Path "$toolsetRoot\bin\Hostx64\x64\nmake.exe" -Arguments '/?'
if ($nmakeOutput -notmatch " $([regex]::Escape($expectedNmakeVersion))") {
    throw "rf: nmake.exe identity differs from the locked tuple"
}

Write-Host 'rf: proving the installed Windows SDK identity'
foreach ($required in @(
        "Include\$expectedSdkGeneration\um\windows.h",
        "Include\$expectedSdkGeneration\ucrt\corecrt.h",
        "Include\$expectedSdkGeneration\shared\winerror.h",
        "Lib\$expectedSdkGeneration\um\x64\kernel32.lib",
        "Lib\$expectedSdkGeneration\ucrt\x64\libucrt.lib")) {
    if (-not (Test-Path -LiteralPath "$sdkRoot\$required")) {
        throw "rf: the Windows SDK $expectedSdkGeneration tree is missing $required"
    }
}

$sdkProduct = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SDKs\Windows\v10.0').ProductVersion
Assert-Equal -Actual $sdkProduct -Expected $expectedSdkProductVersion -Subject 'the Windows SDK product version'

$uninstallKey = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$expectedSdkPackageGuid"
$sdkPackage = (Get-ItemProperty -Path $uninstallKey).DisplayVersion
Assert-Equal -Actual $sdkPackage -Expected $expectedSdkPackageVersion -Subject 'the Windows SDK package version'

Assert-FileIdentity -Path $signTool -Bytes $expectedSignToolBytes -Sha256 $expectedSignToolSha256 `
    -Subject 'the locked SignTool'

Write-Host 'rf: proving the bootstrap transport identity'
$transport = 'C:\Windows\System32\curl.exe'
if (-not (Test-Path -LiteralPath $transport -PathType Leaf)) {
    throw "rf: the bootstrap transport is missing at $transport"
}
$transportOutput = & $transport --version 2>&1 | Out-String
if ($transportOutput -notmatch '^curl (\d+)\.(\d+)\.(\d+) ') {
    throw "rf: the bootstrap transport did not report a parsable curl version"
}
$transportVersion = [version]("$($Matches[1]).$($Matches[2]).$($Matches[3])")
if ($transportVersion -lt [version]'8.19.0') {
    throw "rf: the inbox curl is $transportVersion and the transport record requires 8.19.0 or later"
}

Remove-Item -Recurse -Force 'C:\rf\work'
foreach ($leftover in @('C:\ProgramData\Package Cache', "$env:TEMP\*")) {
    Remove-Item -Recurse -Force $leftover -ErrorAction SilentlyContinue
}

Write-Host 'rf: the Windows container host matches every locked identity'
