#!/bin/sh
# Runs the whole rf-evidence corpus on the Linux container host.
#
# This script executes inside the container, so everything it names is an
# identity the image already proved at build time: the bootstrap CMake outside
# the checkout, the locked package set, and the inbox transport. It acquires the
# locked dependency closure, builds, tests, analyses, and then asks the tool to
# prove the repository about itself.
#
# Every report it writes is a fact recorded by the tool, never a verdict written
# here. The workflow attests the reports; it does not decide what they say.
set -eu

repository_root="$1"
bootstrap_cmake="/opt/rf/bootstrap/cmake-4.4.0-linux-x86_64/bin/cmake"
prepared="${repository_root}/out/prepared/linux-x86_64/tools/cmake/bin"
# The tool refuses a report path outside `out/reports/task-0001/`, which is
# the one place it writes reports, so the lane records beneath it rather than
# inventing a second reports root.
reports="out/reports/task-0001/ci/linux-x86_64"

cd "$repository_root"

# The STD-0007 lane: build instrumented, run the suite, turn the raw profiles
# into one `llvm-cov export`, and let rf-verify measure the change against the
# tier floors. Nothing here decides anything; the tool writes the verdict and
# its exit status carries it.
rf_coverage_lane() {
    host="$1"
    preset="rf-${host}-coverage"
    build="out/build/${preset}"
    llvm="${repository_root}/out/prepared/${host}/tools/llvm/bin"
    coverage="out/coverage"
    # rf-verify writes only beneath `out/reports/verify/`, which is its own
    # report root and not the rf-evidence one used elsewhere in this lane.
    verify_reports="out/reports/verify/ci/${host}"
    mkdir -p "$coverage" "$verify_reports"

    "${prepared}/cmake" --preset "$preset"
    "${prepared}/cmake" --build --preset "$preset"
    rm -rf "${build}/coverage-profiles"
    "${prepared}/ctest" --preset "$preset" --output-on-failure

    # One isolated run per entry point. Every executable defines `main`, an
    # external symbol, so a profile merged across programs keeps one record for
    # it and llvm-cov reports the rest as mismatched and drops their translation
    # unit entirely. Each entry point is therefore measured against a profile
    # from its own program alone, and the merged export leaves main.cpp out so
    # that no source unit is described twice.
    for entry in \
        "verify:rf_verify:Command.RequirementsReportRefusesNoTestReport" \
        "archcheck:rf_archcheck:Command.ArchitectureRulesAreEnumerable" \
        "evidence:rf_evidence:Command.LoadEvidenceIndex"; do
        tool_name="${entry%%:*}"
        rest="${entry#*:}"
        entry_test="${rest#*:}"
        LLVM_PROFILE_FILE="${repository_root}/${build}/coverage-profiles/entry-${tool_name}/rf-%p.profraw" \
            "${prepared}/ctest" --preset "$preset" -R "$entry_test"
    done

    find "${build}/coverage-profiles" -maxdepth 1 -name '*.profraw' > "${coverage}/profile-list.txt"
    "${llvm}/llvm-profdata" merge -sparse -f "${coverage}/profile-list.txt" -o "${coverage}/rawframe.profdata"

    exports="--export ${coverage}/export.json"
    "${llvm}/llvm-cov" export \
        "${build}/tools/rf_evidence/tests/rawframe_tool_rf_evidence_tests" \
        -object "${build}/tools/rf_archcheck/tests/rawframe_tool_rf_archcheck_tests" \
        -object "${build}/tools/rf_verify/tests/rawframe_tool_rf_verify_tests" \
        -object "${build}/tools/rf-evidence" \
        -object "${build}/tools/rf-archcheck" \
        -object "${build}/tools/rf-verify" \
        -instr-profile="${coverage}/rawframe.profdata" --format=text \
        -ignore-filename-regex='.*[/\\]main\.cpp' > "${coverage}/export.json"

    for entry in "verify:rf_verify" "archcheck:rf_archcheck" "evidence:rf_evidence"; do
        tool_name="${entry%%:*}"
        tool_root="${entry#*:}"
        "${llvm}/llvm-profdata" merge -sparse \
            "${build}/coverage-profiles/entry-${tool_name}"/*.profraw \
            -o "${coverage}/entry-${tool_name}.profdata"
        "${llvm}/llvm-cov" export "${build}/tools/rf-${tool_name}" \
            -instr-profile="${coverage}/entry-${tool_name}.profdata" --format=text \
            "tools/${tool_root}/src/main.cpp" > "${coverage}/export-entry-${tool_name}.json"
        exports="${exports} --export ${coverage}/export-entry-${tool_name}.json"
    done

    verify="${build}/tools/rf-verify"

    # The whole-tree figure and the requirement bindings are published on every
    # run. STD-0007 makes both accounting rather than gates, so neither is
    # conditional on there being a diff to measure.
    "$verify" coverage_summary --root "$repository_root" ${exports} \
        --report "${verify_reports}/coverage-summary.json"
    "$verify" requirements_report --root "$repository_root" \
        --test-report "${build}/test_output/verify_test_report.json" \
        --report "${verify_reports}/requirements-report.json"

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
    changed="out/verify/changed.diff"
    if [ ! -f "$changed" ]; then
        echo "rf: no changed-line set was handed in, so the diff-scoped tier floors were not measured" >&2
        return 0
    fi
    "$verify" coverage_floors --root "$repository_root" ${exports} \
        --diff "$changed" --report "${verify_reports}/coverage-floors.json"
}

echo "rf: stage 0, through the bootstrap CMake outside the tree"
"$bootstrap_cmake" --version
"$bootstrap_cmake" \
    -DRF_OPERATION=sync -DRF_HOST=linux-x86_64 -DRF_REPOSITORY_ROOT="$repository_root" \
    -P cmake/bootstrap/sync.cmake

echo "rf: stage 1, the locked dependency closure through the prepared CMake"
"${prepared}/cmake" -DRF_OPERATION=sync -DRF_REPOSITORY_ROOT="$repository_root" -P cmake/sync/linux.cmake

echo "rf: the locked dependency closure built offline through the prepared vcpkg"
"${prepared}/cmake" -DRF_OPERATION=dependencies -DRF_REPOSITORY_ROOT="$repository_root" \
    -P cmake/sync/linux_dependency_build.cmake

echo "rf: configure, build, and test at the debug preset"
"${prepared}/cmake" --preset rf-linux-x86_64-debug
"${prepared}/cmake" --build --preset rf-linux-x86_64-debug
"${prepared}/ctest" --preset rf-linux-x86_64-debug --output-on-failure

echo "rf: configure and build at the analysis preset"
"${prepared}/cmake" --preset rf-linux-x86_64-analysis
"${prepared}/cmake" --build --preset rf-linux-x86_64-analysis

echo "rf: the STD-0007 verification lane at the coverage preset"
rf_coverage_lane linux-x86_64

tool="${repository_root}/out/build/rf-linux-x86_64-debug/tools/rf-evidence"
archcheck="${repository_root}/out/build/rf-linux-x86_64-debug/tools/rf-archcheck"
mkdir -p "${repository_root}/${reports}"

# Each of these reads the repository and writes its own report, so they are
# independent and are run at once. Sequentially they cost six minutes of a
# twenty-minute run, most of it one command rehashing five gigabytes while the
# other cores idle. Every exit status is still collected: a failure anywhere
# fails the lane, and the report a command did not write cannot be attested,
# because the archive step counts what is there.
echo "rf: the repository authorities and the locked closure, in parallel"
pids=""
start() {
    log="$1"
    shift
    ( "$@" > "${log}" 2>&1 ) &
    pids="${pids} $!:${log}"
}

start /tmp/rf-validate.log \
    "$tool" validate repository --root "$repository_root" --report "${reports}/validate-repository.json"
start /tmp/rf-index.log "$tool" load evidence-index --root "$repository_root"
start /tmp/rf-paths.log \
    "$tool" audit paths --root "$repository_root" --report "${reports}/audit-paths.json"
start /tmp/rf-closure.log \
    "$tool" audit shipping-closure --root "$repository_root" --report "${reports}/audit-shipping-closure.json"
start /tmp/rf-licenses.log \
    "$tool" review licenses --root "$repository_root" --report "${reports}/review-licenses.json"
start /tmp/rf-ownership.log \
    "$tool" inspect source-ownership --root "$repository_root" --report "${reports}/source-ownership.json"
start /tmp/rf-offline.log \
    "$tool" verify-offline --root "$repository_root" --host linux-x86_64 --report "${reports}/verify-offline.json"
start /tmp/rf-archcheck.log \
    "$archcheck" check_repository --root "$repository_root" --report "${reports}/archcheck-findings.json"

status=0
for entry in ${pids}; do
    pid="${entry%%:*}"
    log="${entry#*:}"
    if ! wait "${pid}"; then
        status=1
        echo "rf: a repository authority command failed, its output follows" >&2
    fi
    cat "${log}"
done
if [ "${status}" -ne 0 ]; then
    exit 1
fi

# The container runs as root, so everything it wrote into the shared workspace
# is root owned, and the runner user that has to archive the verified artifacts
# afterwards cannot read them. The first attempt at caching them failed exactly
# here, with `tar: Cannot open: Permission denied`, and reported a saved cache
# that did not exist.
#
# The owner is taken from the workspace directory rather than written down. That
# directory was created by the runner, so it names the right user without this
# script knowing a UID, which would be a fact about one runner image rather than
# about the boundary being crossed.
#
# Only the two trees that are cached are handed over. `out/sync` and
# `out/prepared` are larger, are not cached, and are nothing the runner reads.
echo "rf: hand the cached trees to the user that has to archive them"
chown -R "$(stat -c '%u:%g' "$repository_root")" "${repository_root}/out/cache" "${repository_root}/out/bootstrap"

echo "rf: the corpus completed on the Linux container host"
