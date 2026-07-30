# Runs the whole rf-evidence corpus on the Windows container host.
#
# This script executes inside the container, so everything it names is an
# identity the image already proved at build time: the bootstrap CMake outside
# the checkout, the locked Visual Studio and Windows SDK identities, and the
# inbox transport. It acquires the locked dependency closure, builds, tests,
# analyses, and then asks the tool to prove the repository about itself.
#
# Every report it writes is a fact recorded by the tool, never a verdict written
# here. The workflow attests the reports; it does not decide what they say.

param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

$ErrorActionPreference = 'Stop'

# A native tool that exits nonzero has to stop the script. PowerShell does not do
# that for native commands on its own, so each call is followed by an explicit
# check rather than by a hope.
function Invoke-Checked {
    param([string]$Path, [string[]]$Arguments)
    & $Path @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "rf: $Path exited with $LASTEXITCODE"
    }
}

$bootstrapCMake = 'C:\rf\bootstrap\cmake-4.4.0-windows-x86_64\bin\cmake.exe'
$prepared = Join-Path $RepositoryRoot 'out\prepared\windows-x86_64\tools\cmake\bin'
$evidence = 'out/evidence/ci/windows-x86_64'

Set-Location -LiteralPath $RepositoryRoot

Write-Host 'rf: stage 0, through the bootstrap CMake outside the tree'
Invoke-Checked -Path $bootstrapCMake -Arguments @('--version')
Invoke-Checked -Path $bootstrapCMake -Arguments @(
    '-DRF_OPERATION=sync', '-DRF_HOST=windows-x86_64', "-DRF_REPOSITORY_ROOT=$RepositoryRoot",
    '-P', 'cmake/bootstrap/sync.cmake')

Write-Host 'rf: stage 1, the locked dependency closure through the prepared CMake'
Invoke-Checked -Path "$prepared\cmake.exe" -Arguments @(
    '-DRF_OPERATION=sync', "-DRF_REPOSITORY_ROOT=$RepositoryRoot", '-P', 'cmake/sync/windows.cmake')

Write-Host 'rf: the locked dependency closure built offline through the prepared vcpkg'
Invoke-Checked -Path "$prepared\cmake.exe" -Arguments @(
    '-DRF_OPERATION=dependencies', "-DRF_REPOSITORY_ROOT=$RepositoryRoot",
    '-P', 'cmake/sync/windows_dependency_build.cmake')

Write-Host 'rf: configure, build, and test at the debug preset'
Invoke-Checked -Path "$prepared\cmake.exe" -Arguments @('--preset', 'task-0001-windows-x86_64-debug')
Invoke-Checked -Path "$prepared\cmake.exe" -Arguments @('--build', '--preset', 'task-0001-windows-x86_64-debug')
Invoke-Checked -Path "$prepared\ctest.exe" -Arguments @(
    '--preset', 'task-0001-windows-x86_64-debug', '--output-on-failure')

Write-Host 'rf: configure and build at the analysis preset'
Invoke-Checked -Path "$prepared\cmake.exe" -Arguments @('--preset', 'task-0001-windows-x86_64-analysis')
Invoke-Checked -Path "$prepared\cmake.exe" -Arguments @('--build', '--preset', 'task-0001-windows-x86_64-analysis')

$tool = Join-Path $RepositoryRoot 'out\build\task-0001-windows-x86_64-debug\tools\rf-evidence.exe'
New-Item -ItemType Directory -Force -Path (Join-Path $RepositoryRoot $evidence) | Out-Null

Write-Host 'rf: the repository authorities'
Invoke-Checked -Path $tool -Arguments @(
    'validate', 'repository', '--root', $RepositoryRoot, '--report', "$evidence/validate-repository.json")
Invoke-Checked -Path $tool -Arguments @('load', 'evidence-index', '--root', $RepositoryRoot)
Invoke-Checked -Path $tool -Arguments @(
    'audit', 'paths', '--root', $RepositoryRoot, '--report', "$evidence/audit-paths.json")
Invoke-Checked -Path $tool -Arguments @(
    'audit', 'shipping-closure', '--root', $RepositoryRoot, '--report', "$evidence/audit-shipping-closure.json")
Invoke-Checked -Path $tool -Arguments @(
    'review', 'licenses', '--root', $RepositoryRoot, '--report', "$evidence/review-licenses.json")
Invoke-Checked -Path $tool -Arguments @(
    'inspect', 'source-ownership', '--root', $RepositoryRoot, '--report', "$evidence/source-ownership.json")

Write-Host 'rf: the locked closure, verified offline against the lock'
Invoke-Checked -Path $tool -Arguments @(
    'verify-offline', '--root', $RepositoryRoot, '--host', 'windows-x86_64',
    '--report', "$evidence/verify-offline.json")

Write-Host 'rf: the corpus completed on the Windows container host'
