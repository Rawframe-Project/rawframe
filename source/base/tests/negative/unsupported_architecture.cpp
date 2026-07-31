// The architecture half of SPEC-0046's `platform.h` contract, expected to fail to
// compile. Item 19 names the compiler case; the specification gives the
// architecture "the same hard failure", and a rule proved on one of its two
// branches is a rule proved on one of its two branches.

#undef __x86_64__
#undef _M_X64

#include "rawframe/base/platform.h"

int main() {
    return 0;
}
