// SPEC-0046 conformance item 19, expected to fail to compile.
//
// The real compiler is always one of the two, so the only way to reach the
// unsupported branch is to remove the evidence of it. Undefining a predefined
// macro is legal and is exactly what this needs: the header then sees a
// translation unit that names no admitted compiler and must refuse it rather than
// select a fallback, which ADR-0008 makes a pinned platform contract.
//
// The build of this file is a CTest case that passes on the diagnostic below.

#undef __clang__
#undef _MSC_VER

#include "rawframe/base/platform.h"

int main() {
    return 0;
}
