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
evidence="out/evidence/ci/linux-x86_64"

cd "$repository_root"

echo "rf: stage 0, through the bootstrap CMake outside the tree"
"$bootstrap_cmake" --version
"$bootstrap_cmake" \
    -DRF_OPERATION=sync -DRF_HOST=linux-x86_64 -DRF_REPOSITORY_ROOT="$repository_root" \
    -P cmake/bootstrap/sync.cmake

echo "rf: stage 1, the locked dependency closure through the prepared CMake"
"${prepared}/cmake" -DRF_OPERATION=sync -DRF_REPOSITORY_ROOT="$repository_root" -P cmake/sync/linux.cmake

echo "rf: configure, build, and test at the debug preset"
"${prepared}/cmake" --preset task-0001-linux-x86_64-debug
"${prepared}/cmake" --build --preset task-0001-linux-x86_64-debug
"${prepared}/ctest" --preset task-0001-linux-x86_64-debug --output-on-failure

echo "rf: configure and build at the analysis preset"
"${prepared}/cmake" --preset task-0001-linux-x86_64-analysis
"${prepared}/cmake" --build --preset task-0001-linux-x86_64-analysis

tool="${repository_root}/out/build/task-0001-linux-x86_64-debug/tools/rf-evidence"
mkdir -p "${repository_root}/${evidence}"

echo "rf: the repository authorities"
"$tool" validate repository --root "$repository_root" --report "${evidence}/validate-repository.json"
"$tool" load evidence-index --root "$repository_root"
"$tool" audit paths --root "$repository_root" --report "${evidence}/audit-paths.json"
"$tool" audit shipping-closure --root "$repository_root" --report "${evidence}/audit-shipping-closure.json"
"$tool" review licenses --root "$repository_root" --report "${evidence}/review-licenses.json"
"$tool" inspect source-ownership --root "$repository_root" --report "${evidence}/source-ownership.json"

echo "rf: the locked closure, verified offline against the lock"
"$tool" verify-offline --root "$repository_root" --host linux-x86_64 --report "${evidence}/verify-offline.json"

echo "rf: the corpus completed on the Linux container host"
