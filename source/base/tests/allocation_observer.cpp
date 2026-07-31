#include "allocation_observer.h"

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <new>

#ifdef _WIN32
// Both names belong to the Windows SDK's own include contract and cannot carry
// the repository's macro prefix.
// NOLINTNEXTLINE(readability-identifier-naming)
#define WIN32_LEAN_AND_MEAN
// NOLINTNEXTLINE(readability-identifier-naming)
#define NOMINMAX
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

// An allocation observer has to be reachable from a replaced `operator new`,
// which takes no parameters it could receive state through. Process-global is the
// only shape available, and this file is a test fixture rather than a module.
// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables)
std::atomic<bool> watching{false};
std::atomic<bool> observed{false};
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

/// Reports one allocation without allocating. The token goes straight to the
/// platform standard-error primitive because a buffered stream would allocate,
/// and an observer that allocates cannot observe allocation.
void reportObservedAllocation() noexcept {
    if (!watching.load(std::memory_order_acquire)) {
        return;
    }
    observed.store(true, std::memory_order_release);

    const char* token = rawframe::base::test::kAllocationToken;
    const std::size_t kLength = std::strlen(token);
#ifdef _WIN32
    void* handle = GetStdHandle(STD_ERROR_HANDLE);
    if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        static_cast<void>(WriteFile(handle, token, static_cast<DWORD>(kLength), &written, nullptr));
    }
#else
    const auto kResult = ::write(STDERR_FILENO, token, kLength);
    static_cast<void>(kResult);
#endif
}

/// The one allocator behind every replaced form. Exceptions are disabled under
/// ADR-0008, so exhaustion terminates rather than throwing `std::bad_alloc`,
/// which is also what STD-0004 requires of unrestricted heap exhaustion.
// NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
void* allocate(std::size_t bytes) noexcept {
    reportObservedAllocation();
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
    void* memory = std::malloc(bytes == 0 ? 1 : bytes);
    if (memory == nullptr) {
        std::abort();
    }
    return memory;
}

void* allocateAligned(std::size_t bytes, std::align_val_t alignment) noexcept {
    reportObservedAllocation();
    const std::size_t kBoundary = static_cast<std::size_t>(alignment);
    const std::size_t kRounded = ((bytes == 0 ? 1 : bytes) + kBoundary - 1) / kBoundary * kBoundary;
#ifdef _WIN32
    void* memory = _aligned_malloc(kRounded, kBoundary);
#else
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
    void* memory = std::aligned_alloc(kBoundary, kRounded);
#endif
    if (memory == nullptr) {
        std::abort();
    }
    return memory;
}

void release(void* memory) noexcept {
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
    std::free(memory);
}

void releaseAligned(void* memory) noexcept {
#ifdef _WIN32
    _aligned_free(memory);
#else
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
    std::free(memory);
#endif
}

} // namespace

namespace rawframe::base::test {

void beginWatchingAllocations() noexcept {
    observed.store(false, std::memory_order_release);
    watching.store(true, std::memory_order_release);
}

bool allocationObserved() noexcept {
    return observed.load(std::memory_order_acquire);
}

} // namespace rawframe::base::test

// The replacement set. Aligned and unaligned allocation use different platform
// deallocators, so both families are replaced together: replacing one and leaving
// the other to the standard library would pair a replaced allocation with a
// library deallocation.
//
// The parameter-name check compares each definition against the standard
// library's own declaration, whose parameters are named `_Size` and `_Block` in
// the MSVC runtime and something else again in libc++. Adopting either would mean
// writing reserved identifiers here and would still disagree with the other host,
// so the suppression covers the whole set rather than one host's spelling.
// NOLINTBEGIN(readability-inconsistent-declaration-parameter-name)

void* operator new(std::size_t bytes) {
    return allocate(bytes);
}

void* operator new[](std::size_t bytes) {
    return allocate(bytes);
}

void* operator new(std::size_t bytes, const std::nothrow_t& /*tag*/) noexcept {
    return allocate(bytes);
}

void* operator new[](std::size_t bytes, const std::nothrow_t& /*tag*/) noexcept {
    return allocate(bytes);
}

void* operator new(std::size_t bytes, std::align_val_t alignment) {
    return allocateAligned(bytes, alignment);
}

void* operator new[](std::size_t bytes, std::align_val_t alignment) {
    return allocateAligned(bytes, alignment);
}

void* operator new(std::size_t bytes, std::align_val_t alignment, const std::nothrow_t& /*tag*/) noexcept {
    return allocateAligned(bytes, alignment);
}

void* operator new[](std::size_t bytes, std::align_val_t alignment, const std::nothrow_t& /*tag*/) noexcept {
    return allocateAligned(bytes, alignment);
}

void operator delete(void* memory) noexcept {
    release(memory);
}

void operator delete[](void* memory) noexcept {
    release(memory);
}

void operator delete(void* memory, std::size_t /*size*/) noexcept {
    release(memory);
}

void operator delete[](void* memory, std::size_t /*size*/) noexcept {
    release(memory);
}

void operator delete(void* memory, const std::nothrow_t& /*tag*/) noexcept {
    release(memory);
}

void operator delete[](void* memory, const std::nothrow_t& /*tag*/) noexcept {
    release(memory);
}

void operator delete(void* memory, std::align_val_t /*alignment*/) noexcept {
    releaseAligned(memory);
}

void operator delete[](void* memory, std::align_val_t /*alignment*/) noexcept {
    releaseAligned(memory);
}

void operator delete(void* memory, std::size_t /*size*/, std::align_val_t /*alignment*/) noexcept {
    releaseAligned(memory);
}

void operator delete[](void* memory, std::size_t /*size*/, std::align_val_t /*alignment*/) noexcept {
    releaseAligned(memory);
}

void operator delete(void* memory, std::align_val_t /*alignment*/, const std::nothrow_t& /*tag*/) noexcept {
    releaseAligned(memory);
}

void operator delete[](void* memory, std::align_val_t /*alignment*/, const std::nothrow_t& /*tag*/) noexcept {
    releaseAligned(memory);
}

// NOLINTEND(readability-inconsistent-declaration-parameter-name)
