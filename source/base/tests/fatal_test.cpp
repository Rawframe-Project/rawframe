// SPEC-0046 conformance items 9 through 13, and PLAN-0002's fatal-path list.
//
// Everything here runs in a death-test child, and not for convenience. The
// handler slot and the re-entry flag are process-global and write-once, so a case
// that installs a handler has spent the process's one installation. A child per
// case is what lets each case start from the state a fresh process has, which is
// also the state SPEC-0046 describes: the fatal path must work before any
// composition root exists.

#include "allocation_observer.h"
#include "rawframe/base/assert.h"
#include "rawframe/base/fatal.h"

#include <cstddef>
#include <cstring>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <new>
#include <source_location>
#include <string_view>

#ifdef _WIN32
// Both names belong to the Windows SDK's own include contract and cannot carry
// the repository's macro prefix.
// NOLINTNEXTLINE(readability-identifier-naming)
#define WIN32_LEAN_AND_MEAN
// NOLINTNEXTLINE(readability-identifier-naming)
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

using rawframe::base::FatalReason;
using rawframe::base::FatalRecord;
using rawframe::base::freezeFatalHandler;
using rawframe::base::installFatalHandler;
using rawframe::base::raiseFatal;

/// Writes to the standard error stream without allocating or locking, so a case
/// can report from inside a fatal handler and from inside an allocation
/// observation window.
void writeToken(const char* token) noexcept {
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

void handlerA(const FatalRecord& /*record*/) noexcept {
    writeToken("[handler-a-ran]");
}

void handlerB(const FatalRecord& /*record*/) noexcept {
    writeToken("[handler-b-ran]");
}

void handlerC(const FatalRecord& /*record*/) noexcept {
    writeToken("[handler-c-ran]");
}

/// A handler that fails the way a handler actually fails: by entering the fatal
/// path again from inside itself.
void reentrantHandler(const FatalRecord& /*record*/) noexcept {
    RAWFRAME_PANIC("the failure inside the handler");
}

/// Makes the default handler's write target fail, without changing anything else
/// about the path.
void breakTheStandardErrorStream() noexcept {
#ifdef _WIN32
    static_cast<void>(SetStdHandle(STD_ERROR_HANDLE, nullptr));
#else
    static_cast<void>(::close(STDERR_FILENO));
#endif
}

/// The other way a Windows write target fails: a handle that is present and
/// invalid rather than absent. The default handler answers both, and one case
/// can only produce the first of the two. On a platform whose standard error is
/// a descriptor there is one failure and this is it.
void invalidateTheStandardErrorHandle() noexcept {
#ifdef _WIN32
    static_cast<void>(SetStdHandle(STD_ERROR_HANDLE, INVALID_HANDLE_VALUE));
#else
    static_cast<void>(::close(STDERR_FILENO));
#endif
}

} // namespace

// Item 10. No handler, no composition root, no prior state: the default handler
// runs and the process terminates.
TEST(FatalPath, TerminatesThroughTheDefaultHandlerBeforeAnyCompositionRoot) {
    RecordProperty("requirement", "SPEC-0046:item-10-default-handler-before-composition");

    EXPECT_DEATH({ RAWFRAME_PANIC("nothing has been composed yet"); }, "rawframe fatal: Panic");
}

TEST(FatalPath, ReportsTheConditionAndTheMessageTheCallSiteGave) {
    RecordProperty("requirement", "SPEC-0046:item-10-default-handler-before-composition");

    EXPECT_DEATH(
        { RAWFRAME_CHECK(1 == 2, "one is not two"); },
        testing::AllOf(testing::HasSubstr("CheckFailed"),
                       testing::HasSubstr("1 == 2"),
                       testing::HasSubstr("one is not two"),
                       testing::HasSubstr("fatal_test.cpp")));
}

// Item 9. Four installation answers, and the one that matters after them: the
// handler installed first is still the handler that runs. Every step is inside
// the child, because the parent's slot is not the child's on every host.
TEST(FatalPath, AcceptsOneHandlerAndRefusesEveryOtherInstallation) {
    RecordProperty("requirement", "SPEC-0046:item-9-single-installation-before-freeze");

    EXPECT_DEATH(
        {
            writeToken(installFatalHandler(nullptr) ? "[null:accepted]" : "[null:refused]");
            writeToken(installFatalHandler(&handlerA) ? "[first:accepted]" : "[first:refused]");
            writeToken(installFatalHandler(&handlerB) ? "[second:accepted]" : "[second:refused]");
            freezeFatalHandler();
            freezeFatalHandler();
            writeToken(installFatalHandler(&handlerC) ? "[frozen:accepted]" : "[frozen:refused]");
            RAWFRAME_PANIC("the installed handler must be the first one");
        },
        testing::AllOf(testing::HasSubstr("[null:refused]"),
                       testing::HasSubstr("[first:accepted]"),
                       testing::HasSubstr("[second:refused]"),
                       testing::HasSubstr("[frozen:refused]"),
                       testing::HasSubstr("[handler-a-ran]"),
                       testing::Not(testing::HasSubstr("[handler-b-ran]")),
                       testing::Not(testing::HasSubstr("[handler-c-ran]"))));
}

// The freeze closes installation even when nothing was installed before it, which
// is the case the composition root actually produces.
TEST(FatalPath, RefusesInstallationAfterAFreezeWithNothingInstalled) {
    RecordProperty("requirement", "SPEC-0046:item-9-single-installation-before-freeze");

    EXPECT_DEATH(
        {
            freezeFatalHandler();
            writeToken(installFatalHandler(&handlerA) ? "[frozen:accepted]" : "[frozen:refused]");
            RAWFRAME_PANIC("the freeze closed installation");
        },
        testing::AllOf(testing::HasSubstr("[frozen:refused]"),
                       testing::Not(testing::HasSubstr("[handler-a-ran]")),
                       testing::HasSubstr("rawframe fatal: Panic")));
}

// A handler that returns despite its contract has failed in exactly the way
// SPEC-0004 anticipates, and the path terminates anyway. `handlerA` returns, so
// every case above already relies on this; the claim is worth its own name.
TEST(FatalPath, TerminatesEvenWhenTheHandlerReturns) {
    RecordProperty("requirement", "SPEC-0046:item-9-single-installation-before-freeze");

    EXPECT_DEATH(
        {
            static_cast<void>(installFatalHandler(&handlerA));
            RAWFRAME_PANIC("the handler will return");
        },
        testing::HasSubstr("[handler-a-ran]"));
}

// Item 11. The default handler's write target fails and the path still ends.
TEST(FatalPath, TerminatesWhenTheDefaultHandlerCannotWrite) {
    RecordProperty("requirement", "SPEC-0046:item-11-terminates-when-the-write-fails");

    EXPECT_DEATH(
        {
            breakTheStandardErrorStream();
            RAWFRAME_PANIC("there is nowhere to write this");
        },
        "");
}

// The same claim for the other failing handle. A case that only ever hands the
// default handler an absent handle leaves the invalid one untested, and the two
// are different values answered by different comparisons.
TEST(FatalPath, TerminatesWhenTheStandardErrorHandleIsInvalidRatherThanAbsent) {
    RecordProperty("requirement", "SPEC-0046:item-11-terminates-when-the-write-fails");

    EXPECT_DEATH(
        {
            invalidateTheStandardErrorHandle();
            RAWFRAME_PANIC("the handle is invalid rather than missing");
        },
        "");
}

// Item 12. Re-entry terminates without recursing, and is distinguishable from the
// failure that started it.
TEST(FatalPath, TerminatesOnReentryAndSaysSo) {
    RecordProperty("requirement", "SPEC-0046:item-12-reentry-is-distinguishable");

    EXPECT_DEATH(
        {
            static_cast<void>(installFatalHandler(&reentrantHandler));
            RAWFRAME_PANIC("the first failure");
        },
        testing::HasSubstr("rawframe fatal: FatalPathReentered"));
}

// Item 13. Observed rather than read: every allocation between the window opening
// and the process ending writes a token, and the token is absent.
TEST(FatalPath, AllocatesNothingOnTheWayToTermination) {
    RecordProperty("requirement", "SPEC-0046:item-13-fatal-path-allocates-nothing");

    EXPECT_DEATH(
        {
            rawframe::base::test::beginWatchingAllocations();
            RAWFRAME_PANIC("the fatal path allocates nothing");
        },
        testing::AllOf(testing::HasSubstr("rawframe fatal: Panic"),
                       testing::Not(testing::HasSubstr(rawframe::base::test::kAllocationToken))));
}

// And the observer is not vacuous. A fixture that could never report would pass
// the case above no matter what the fatal path did.
TEST(FatalPath, TheAllocationObserverReportsAnAllocationWhenThereIsOne) {
    RecordProperty("requirement", "SPEC-0046:item-13-fatal-path-allocates-nothing");

    EXPECT_DEATH(
        {
            rawframe::base::test::beginWatchingAllocations();
            // An explicit call rather than a new-expression. The standard lets a
            // compiler omit the allocation a new-expression performs, and the
            // optimized configurations do exactly that, which turned this case
            // into one that passed in debug and failed everywhere else. An
            // explicit call to the allocation function is an ordinary call and
            // cannot be elided. The size is volatile so that nothing upstream
            // can be constant folded either.
            volatile std::size_t requested = sizeof(int);
            void* deliberate = ::operator new(requested);
            ::operator delete(deliberate);
            RAWFRAME_PANIC("an allocation happened first");
        },
        testing::HasSubstr(rawframe::base::test::kAllocationToken));
}

// The macros never produce these three records, and the default handler formats
// all of them. `raiseFatal` is public, so a caller that is not a macro is a
// supported caller, and everything below is what such a caller can hand it.

// A reason the enumeration does not name is a value the type admits: the
// underlying type is an octet and every octet is a valid value of it. The
// handler names it rather than writing whatever happened to be in the buffer.
TEST(FatalPath, NamesAReasonTheEnumerationDoesNotDefine) {
    RecordProperty("requirement", "SPEC-0046:item-10-default-handler-before-composition");

    EXPECT_DEATH(
        {
            raiseFatal(FatalRecord{
                .reason = static_cast<FatalReason>(200),
                .location = std::source_location::current(),
                .condition = std::string_view{},
                .message = std::string_view{"a reason with no name"},
                .threadIdentity = 0,
            });
        },
        testing::HasSubstr("rawframe fatal: Unknown"));
}

// The re-entry reason reaches the handler when a caller states it directly,
// which is not the same path as the re-entry the flag detects: that one writes
// one constant line and never formats a record at all.
TEST(FatalPath, NamesTheReentryReasonWhenACallerStatesItDirectly) {
    RecordProperty("requirement", "SPEC-0046:item-12-reentry-is-distinguishable");

    EXPECT_DEATH(
        {
            raiseFatal(FatalRecord{
                .reason = FatalReason::FatalPathReentered,
                .location = std::source_location::current(),
                .condition = std::string_view{},
                .message = std::string_view{"stated rather than detected"},
                .threadIdentity = 0,
            });
        },
        testing::AllOf(testing::HasSubstr("rawframe fatal: FatalPathReentered"),
                       testing::HasSubstr("stated rather than detected")));
}

// A caller that already knows which thread it is on keeps its own answer. The
// path fills the field only when it is unset, and a case that never sets it
// cannot tell the two behaviors apart.
TEST(FatalPath, KeepsTheThreadIdentityTheCallerSupplied) {
    RecordProperty("requirement", "SPEC-0046:item-10-default-handler-before-composition");

    EXPECT_DEATH(
        {
            raiseFatal(FatalRecord{
                .reason = FatalReason::Panic,
                .location = std::source_location::current(),
                .condition = std::string_view{},
                .message = std::string_view{"the caller named its thread"},
                .threadIdentity = 4242,
            });
        },
        testing::HasSubstr("thread: 4242"));
}

// A record whose location was never set is still formatted. The location is an
// ordinary member and a caller may leave it default constructed, which makes
// the line and the column zero: the one value a loop that tests before it
// writes would drop, and the handler writes it.
TEST(FatalPath, FormatsARecordWhoseLocationWasNeverSet) {
    RecordProperty("requirement", "SPEC-0046:item-10-default-handler-before-composition");

    EXPECT_DEATH(
        {
            raiseFatal(FatalRecord{
                .reason = FatalReason::Panic,
                .location = std::source_location{},
                .condition = std::string_view{},
                .message = std::string_view{"there is no call site here"},
                .threadIdentity = 7,
            });
        },
        testing::AllOf(testing::HasSubstr(":0:0"), testing::HasSubstr("there is no call site here")));
}
