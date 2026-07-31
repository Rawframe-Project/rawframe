#pragma once

// SPEC-0046 conformance item 13 asks that `raiseFatal` be proved allocation-free
// by an observing fixture rather than by reading the code. Replacing the global
// allocation functions is that fixture: every heap allocation the fatal path
// could make goes through one of them, and the fatal path makes none.
//
// Watching is off until a test turns it on, because GoogleTest itself allocates
// and an observer that was always on would report its own harness. The window is
// opened immediately before the fatal call and never closed, since the process is
// terminating either way.

namespace rawframe::base::test {

/// Opens the observation window. Every allocation after this point writes the
/// token below to the standard error stream, where a death-test matcher can see
/// it, and sets the flag `allocationObserved` reports.
void beginWatchingAllocations() noexcept;

/// Whether an allocation happened since the window opened.
[[nodiscard]] bool allocationObserved() noexcept;

/// The exact bytes an observed allocation writes. A death test asserts its
/// absence, so it is spelled once and shared rather than duplicated as a literal.
inline constexpr const char* kAllocationToken = "rawframe-test-observed-an-allocation";

} // namespace rawframe::base::test
