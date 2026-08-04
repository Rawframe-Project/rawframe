// SPEC-0046 conformance item 7, second half, expected to fail to compile.
//
// SPEC-0004 permits removing `RAWFRAME_ASSERT` completely in the shipping
// configuration. Removing the condition text as well would mean an assertion
// naming a renamed variable compiles in shipping and fails in debug, so the
// defect is found by whichever configuration someone happened to build. The
// shipping expansion therefore keeps the condition in an unevaluated operand.
//
// This file names an identifier that does not exist. It must fail to compile in
// every configuration, including shipping, where the condition is never
// evaluated. The build of this file is a CTest case that passes on the
// diagnostic.

#include "rawframe/base/assert.h"

int main() {
    RAWFRAME_ASSERT(theIdentifierThisAssertionNamesDoesNotExist == 1, "the condition is still type checked");
    return 0;
}
