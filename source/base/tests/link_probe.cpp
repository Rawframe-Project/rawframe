// SPEC-0046 conformance item 3.
//
// A header check cannot see a link-time dependency, so this executable links
// `rawframe.base` and nothing else and then runs. It uses one symbol from the
// static library rather than only headers, because a probe that touched no
// out-of-line symbol would link even if the library were empty.
//
// Today the claim that it links neither `rawframe.result` nor
// `rawframe.diagnostics` nor `rawframe.execution` is satisfied by their not
// existing. The probe is here so that the claim keeps being checked once they do.

#include "rawframe/base/bits128.h"
#include "rawframe/base/fatal.h"

#include <array>
#include <cstdio>
#include <span>
#include <string_view>

int main() {
    // An out-of-line symbol from the static library. Installing a null handler is
    // refused and changes nothing, which makes it the one call that reaches the
    // library without altering process state or terminating.
    if (rawframe::base::installFatalHandler(nullptr)) {
        return 1;
    }

    constexpr rawframe::base::Bits128 kValue{0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL};
    std::array<char, rawframe::base::kBits128HexDigits> digits{};
    rawframe::base::formatBits128Hex(kValue, std::span<char, rawframe::base::kBits128HexDigits>{digits});

    const auto kParsed = rawframe::base::parseBits128Hex(std::string_view{digits.data(), digits.size()});
    if (!kParsed.parsed || kParsed.value != kValue) {
        return 1;
    }

    std::fputs("rawframe.base links and runs alone\n", stdout);
    return 0;
}
