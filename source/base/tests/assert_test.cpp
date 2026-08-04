// SPEC-0046 conformance items 6, 7, and 8.
//
// Item 6 asks for nine cases, not three: each of the three macros in each of the
// three configurations. A test executable is compiled in one configuration at a
// time, so the nine live here as three cases each carrying the branch its
// configuration selects, and the three configurations are run by the lane. The
// branch is on `RAWFRAME_ASSERTIONS` because that is the whole of what the
// configuration projects; a test that read the configuration identifier instead
// would be asserting the projection rather than the behavior.

#include "rawframe/base/assert.h"

#include <gtest/gtest.h>

#ifndef RAWFRAME_ASSERTIONS
#error "the test build did not receive the assertion level projection"
#endif

namespace {

// A failing condition the compiler is not free to decide. `1 == 2` would be a
// constant expression, and whether the optimizer keeps a decision it has already
// answered is not a property the test should depend on: the three configurations
// optimize differently and a case that quietly stopped exercising the failing
// branch in two of them would still pass in all three. A volatile read cannot be
// folded at any level. The name says two because that is the value; the cases
// below compare it against one.
int twoAtRunTime() {
    volatile int value = 2;
    return value;
}

// The failing call sites live here rather than inside the death-test macro, and
// the reason is a property of the coverage tooling rather than a preference. A
// Rawframe macro expanded inside a GoogleTest macro has its branch regions
// attributed to the GoogleTest header, which is external and carries no coverage
// mapping, so the outcome executes in the death-test child and is reported
// nowhere at all. An ordinary function keeps the same behavior and puts the
// region back in a file that is measured.
void assertAConditionThatDoesNotHold() {
    RAWFRAME_ASSERT(twoAtRunTime() == 1, "two is not one");
}

void checkAConditionThatDoesNotHold() {
    RAWFRAME_CHECK(twoAtRunTime() == 1, "two is not one");
}

} // namespace

// Item 6, RAWFRAME_ASSERT.
TEST(AssertionMacros, AssertIsEvaluatedOnlyWhereTheConfigurationSaysItIs) {
    RecordProperty("requirement", "SPEC-0046:item-6-macro-behavior-per-configuration");
    RecordProperty("requirement", "SPEC-0046:item-7-shipping-assert-is-not-evaluated");

    // The condition carries an observable effect on purpose. SPEC-0004 forbids
    // that in real code and the side-effect lint enforces it there; here it is
    // the instrument, because non-evaluation cannot be observed any other way.
    int evaluations = 0;
    RAWFRAME_ASSERT(++evaluations >= 0, "the condition holds");

#if RAWFRAME_ASSERTIONS == 2
    EXPECT_EQ(evaluations, 1) << "a full-assertion configuration must evaluate the condition";
#else
    EXPECT_EQ(evaluations, 0) << "a contract-only configuration must not evaluate the condition";
#endif
}

TEST(AssertionMacros, AssertIsNonReturningOnFailureWhereItIsEvaluated) {
    RecordProperty("requirement", "SPEC-0046:item-6-macro-behavior-per-configuration");

#if RAWFRAME_ASSERTIONS == 2
    EXPECT_DEATH({ assertAConditionThatDoesNotHold(); }, "rawframe fatal: AssertionFailed");
#else
    // Removed from the shipping configuration, so a failing condition is not a
    // failure at all. Reaching the next statement is the assertion.
    bool reached = false;
    assertAConditionThatDoesNotHold();
    reached = true;
    EXPECT_TRUE(reached) << "a contract-only configuration must not terminate on a failed assertion";
#endif
}

// Item 6, RAWFRAME_CHECK. Always on, in every configuration, with no branch.
TEST(AssertionMacros, CheckIsNonReturningOnFailureInEveryConfiguration) {
    RecordProperty("requirement", "SPEC-0046:item-6-macro-behavior-per-configuration");

    EXPECT_DEATH({ checkAConditionThatDoesNotHold(); }, "rawframe fatal: CheckFailed");
}

TEST(AssertionMacros, CheckReturnsWhenItsConditionHolds) {
    RecordProperty("requirement", "SPEC-0046:item-6-macro-behavior-per-configuration");

    bool reached = false;
    RAWFRAME_CHECK(1 == 1, "one is one");
    reached = true;
    EXPECT_TRUE(reached);
}

// Item 8. Counted rather than read off the macro definition, because a macro that
// names its condition twice compiles and passes every other test in this file.
TEST(AssertionMacros, CheckEvaluatesItsConditionExactlyOnce) {
    RecordProperty("requirement", "SPEC-0046:item-8-check-evaluates-once");

    int evaluations = 0;
    RAWFRAME_CHECK(++evaluations > 0, "the condition holds");
    EXPECT_EQ(evaluations, 1) << "the check evaluated its condition " << evaluations << " times";
}

// Item 6, RAWFRAME_PANIC. Non-returning everywhere, with no condition to evaluate.
TEST(AssertionMacros, PanicIsNonReturningInEveryConfiguration) {
    RecordProperty("requirement", "SPEC-0046:item-6-macro-behavior-per-configuration");

    EXPECT_DEATH({ RAWFRAME_PANIC("this is unconditional"); }, "rawframe fatal: Panic");
}

TEST(AssertionMacros, PanicCarriesNoConditionText) {
    RecordProperty("requirement", "SPEC-0046:item-6-macro-behavior-per-configuration");

    // The record's condition field is empty for Panic, so the default handler
    // writes no condition line at all.
    EXPECT_DEATH({ RAWFRAME_PANIC("this is unconditional"); }, "rawframe fatal: Panic");
    EXPECT_DEATH({ RAWFRAME_PANIC("this is unconditional"); }, "message: this is unconditional");
}

// The macros are usable where a statement is expected and bind to the nearer
// `else`, which is what the `do { } while (false)` wrapper is for. A macro that
// broke this would be found by the first caller and not by any case above.
TEST(AssertionMacros, AreSingleStatementsInEveryConfiguration) {
    int taken = 0;
    {
        RAWFRAME_CHECK(1 == 1, "the taken branch");
    }
    EXPECT_EQ(taken, 0);

    {
        RAWFRAME_ASSERT(1 == 1, "the taken branch");
    }
    EXPECT_EQ(taken, 0);
}
