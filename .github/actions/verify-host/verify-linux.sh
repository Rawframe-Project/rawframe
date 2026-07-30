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
"${prepared}/cmake" --preset task-0001-linux-x86_64-debug
"${prepared}/cmake" --build --preset task-0001-linux-x86_64-debug
"${prepared}/ctest" --preset task-0001-linux-x86_64-debug --output-on-failure

echo "rf: configure and build at the analysis preset"
"${prepared}/cmake" --preset task-0001-linux-x86_64-analysis
"${prepared}/cmake" --build --preset task-0001-linux-x86_64-analysis

tool="${repository_root}/out/build/task-0001-linux-x86_64-debug/tools/rf-evidence"
archcheck="${repository_root}/out/build/task-0001-linux-x86_64-debug/tools/rf-archcheck"
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
