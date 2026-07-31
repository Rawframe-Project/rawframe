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

# The STD-0007 lane: build instrumented, run the suite, turn the raw profiles
# into one `llvm-cov export`, and let rf-verify measure the change against the
# tier floors. Nothing here decides anything; the tool writes the verdict and
# its exit status carries it.
function Invoke-CoverageLane {
    param([string]$RepositoryRoot, [string]$Prepared, [string]$Host_)

    $preset = "rf-$Host_-coverage"
    $build = "out/build/$preset"
    $llvm = Join-Path $RepositoryRoot "out\prepared\$Host_\tools\llvm\bin"
    $coverage = 'out/coverage'
    # rf-verify writes only beneath `out/reports/verify/`, which is its own
    # report root and not the rf-evidence one used elsewhere in this lane.
    $verifyReports = "out/reports/verify/ci/$Host_"
    New-Item -ItemType Directory -Force -Path $coverage, $verifyReports | Out-Null

    Invoke-Checked -Path "$Prepared\cmake.exe" -Arguments @('--preset', $preset)
    Invoke-Checked -Path "$Prepared\cmake.exe" -Arguments @('--build', '--preset', $preset)
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$build/coverage-profiles"

    # `%m` rather than the compiled-in `%p`, and the reason is a measurement
    # defect this lane actually produced. `%p` is the process identifier, and the
    # suite now runs one process per test case: the first run past eight hundred
    # cases wrote seven hundred and five raw profiles, because the operating
    # system reuses process identifiers and a later process silently truncated an
    # earlier one's file. The lost profiles were not distributed evenly, so whole
    # test cases read as never executed and the diff-scoped floors failed against
    # code the suite demonstrably ran.
    #
    # `%m` names the file after the instrumented binary's own signature and puts
    # the profiling runtime into merge mode, where every process of that binary
    # merges its counters into the one file under a lock. Eight files replace
    # seven hundred, and nothing is lost to a reused identifier. A process that
    # loses the environment variable still falls back to the compiled-in `%p`
    # destination in the same directory, so it is collected either way.
    $env:LLVM_PROFILE_FILE = Join-Path $RepositoryRoot "$build/coverage-profiles/rf-%m.profraw"
    try {
        Invoke-Checked -Path "$Prepared\ctest.exe" -Arguments @('--preset', $preset, '--output-on-failure')
    }
    finally {
        Remove-Item Env:\LLVM_PROFILE_FILE
    }

    # One isolated run per entry point. Every executable defines `main`, an
    # external symbol, so a profile merged across programs keeps one record for
    # it and llvm-cov reports the rest as mismatched and drops their translation
    # unit entirely. Each entry point is therefore measured against a profile
    # from its own program alone, and the merged export leaves main.cpp out so
    # that no source unit is described twice.
    $entryPoints = @(
        @{ Name = 'verify'; Root = 'rf_verify'; Test = 'Command.RequirementsReportRefusesNoTestReport' },
        @{ Name = 'archcheck'; Root = 'rf_archcheck'; Test = 'Command.ArchitectureRulesAreEnumerable' },
        @{ Name = 'evidence'; Root = 'rf_evidence'; Test = 'Command.LoadEvidenceIndex' })
    foreach ($entry in $entryPoints) {
        $env:LLVM_PROFILE_FILE = Join-Path $RepositoryRoot "$build/coverage-profiles/entry-$($entry.Name)/rf-%m.profraw"
        try {
            Invoke-Checked -Path "$Prepared\ctest.exe" -Arguments @('--preset', $preset, '-R', $entry.Test)
        }
        finally {
            Remove-Item Env:\LLVM_PROFILE_FILE
        }
    }

    $profiles = Get-ChildItem -Path "$build/coverage-profiles" -Filter '*.profraw' -File |
        ForEach-Object { $_.FullName }
    Set-Content -LiteralPath "$coverage/profile-list.txt" -Value $profiles
    Invoke-Checked -Path "$llvm\llvm-profdata.exe" -Arguments @(
        'merge', '-sparse', '-f', "$coverage/profile-list.txt", '-o', "$coverage/rawframe.profdata")

    $exports = @('--export', "$coverage/export.json")
    & "$llvm\llvm-cov.exe" export `
        "$build/tools/rf_evidence/tests/rawframe_tool_rf_evidence_tests.exe" `
        -object "$build/tools/rf_archcheck/tests/rawframe_tool_rf_archcheck_tests.exe" `
        -object "$build/tools/rf_verify/tests/rawframe_tool_rf_verify_tests.exe" `
        -object "$build/tools/rf-evidence.exe" `
        -object "$build/tools/rf-archcheck.exe" `
        -object "$build/tools/rf-verify.exe" `
        -object "$build/source/base/tests/rawframe_base_tests.exe" `
        -instr-profile="$coverage/rawframe.profdata" --format=text `
        -ignore-filename-regex='.*[/\\]main\.cpp' > "$coverage/export.json"
    if ($LASTEXITCODE -ne 0) { throw "rf: llvm-cov export exited with $LASTEXITCODE" }

    foreach ($entry in $entryPoints) {
        $entryProfiles = Get-ChildItem -Path "$build/coverage-profiles/entry-$($entry.Name)" -Filter '*.profraw' -File |
            ForEach-Object { $_.FullName }
        Invoke-Checked -Path "$llvm\llvm-profdata.exe" -Arguments (
            @('merge', '-sparse') + $entryProfiles + @('-o', "$coverage/entry-$($entry.Name).profdata"))
        & "$llvm\llvm-cov.exe" export "$build/tools/rf-$($entry.Name).exe" `
            -instr-profile="$coverage/entry-$($entry.Name).profdata" --format=text `
            "tools/$($entry.Root)/src/main.cpp" > "$coverage/export-entry-$($entry.Name).json"
        if ($LASTEXITCODE -ne 0) { throw "rf: llvm-cov export exited with $LASTEXITCODE" }
        $exports += @('--export', "$coverage/export-entry-$($entry.Name).json")
    }

    $verify = "$build/tools/rf-verify.exe"

    # The whole-tree figure and the requirement bindings are published on every
    # run. STD-0007 makes both accounting rather than gates, so neither is
    # conditional on there being a diff to measure.
    Invoke-Checked -Path $verify -Arguments (@('coverage_summary', '--root', $RepositoryRoot) + $exports +
        @('--report', "$verifyReports/coverage-summary.json"))
    Invoke-Checked -Path $verify -Arguments @(
        'requirements_report', '--root', $RepositoryRoot,
        '--test-report', "$build/test_output/verify_test_report.json",
        '--report', "$verifyReports/requirements-report.json")

    # The floors are diff scoped, so they need the set of lines the change
    # touched. That set is a fact about the event rather than about this host,
    # and it is produced by the workflow step that already has git and the
    # history, then handed in as a file. Nothing here runs git: the container is
    # not required to carry it, and the verification tool is a reader of
    # committed and generated inputs rather than something that executes
    # processes, which SPEC-0017 forbids it by name.
    #
    # A run with no changed-line set reports the whole-tree figure above and says
    # the floors were not measured. It never reports a gate that did not run.
    $changed = 'out/verify/changed.diff'
    if (-not (Test-Path -LiteralPath $changed -PathType Leaf)) {
        Write-Host 'rf: no changed-line set was handed in, so the diff-scoped tier floors were not measured'
        return
    }
    Invoke-Checked -Path $verify -Arguments (@('coverage_floors', '--root', $RepositoryRoot) + $exports +
        @('--diff', $changed, '--report', "$verifyReports/coverage-floors.json"))
}

$bootstrapCMake = 'C:\rf\bootstrap\cmake-4.4.0-windows-x86_64\bin\cmake.exe'
$prepared = Join-Path $RepositoryRoot 'out\prepared\windows-x86_64\tools\cmake\bin'
# The tool refuses a report path outside `out/reports/task-0001/`, which is
# the one place it writes reports, so the lane records beneath it rather than
# inventing a second reports root.
$reports = 'out/reports/task-0001/ci/windows-x86_64'

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
Invoke-Checked -Path "$prepared\cmake.exe" -Arguments @('--preset', 'rf-windows-x86_64-debug')
Invoke-Checked -Path "$prepared\cmake.exe" -Arguments @('--build', '--preset', 'rf-windows-x86_64-debug')
Invoke-Checked -Path "$prepared\ctest.exe" -Arguments @(
    '--preset', 'rf-windows-x86_64-debug', '--output-on-failure')

Write-Host 'rf: configure and build at the analysis preset'
Invoke-Checked -Path "$prepared\cmake.exe" -Arguments @('--preset', 'rf-windows-x86_64-analysis')
Invoke-Checked -Path "$prepared\cmake.exe" -Arguments @('--build', '--preset', 'rf-windows-x86_64-analysis')

Write-Host 'rf: the STD-0007 verification lane at the coverage preset'
Invoke-CoverageLane -RepositoryRoot $RepositoryRoot -Prepared $prepared -Host_ 'windows-x86_64'

$tool = Join-Path $RepositoryRoot 'out\build\rf-windows-x86_64-debug\tools\rf-evidence.exe'
New-Item -ItemType Directory -Force -Path (Join-Path $RepositoryRoot $reports) | Out-Null

Write-Host 'rf: the repository authorities'
Invoke-Checked -Path $tool -Arguments @(
    'validate', 'repository', '--root', $RepositoryRoot, '--report', "$reports/validate-repository.json")
Invoke-Checked -Path $tool -Arguments @('load', 'evidence-index', '--root', $RepositoryRoot)
Invoke-Checked -Path $tool -Arguments @(
    'audit', 'paths', '--root', $RepositoryRoot, '--report', "$reports/audit-paths.json")
Invoke-Checked -Path $tool -Arguments @(
    'audit', 'shipping-closure', '--root', $RepositoryRoot, '--report', "$reports/audit-shipping-closure.json")
Invoke-Checked -Path $tool -Arguments @(
    'review', 'licenses', '--root', $RepositoryRoot, '--report', "$reports/review-licenses.json")
Invoke-Checked -Path $tool -Arguments @(
    'inspect', 'source-ownership', '--root', $RepositoryRoot, '--report', "$reports/source-ownership.json")

Write-Host 'rf: architecture conformance over this repository'
$archcheck = Join-Path $RepositoryRoot 'out\build\rf-windows-x86_64-debug\tools\rf-archcheck.exe'
Invoke-Checked -Path $archcheck -Arguments @(
    'check_repository', '--root', $RepositoryRoot, '--report', "$reports/archcheck-findings.json")

Write-Host 'rf: the locked closure, verified offline against the lock'
Invoke-Checked -Path $tool -Arguments @(
    'verify-offline', '--root', $RepositoryRoot, '--host', 'windows-x86_64',
    '--report', "$reports/verify-offline.json")

Write-Host 'rf: the corpus completed on the Windows container host'
