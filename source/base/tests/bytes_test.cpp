// ADR-0075 class 3. The substance of `bytes.h` is a set of rules, and the
// declarations are two aliases. What a test can hold is that the aliases are
// exactly the standard vocabulary they claim to be, since the value of an alias
// here is entirely that it names one agreed spelling: an alias that quietly
// became something else would let two modules mean different things by the same
// word, which is the failure the rules exist to prevent.

#include "rawframe/base/bytes.h"

#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <span>
#include <type_traits>

namespace {

using rawframe::base::ByteSpan;
using rawframe::base::MutableByteSpan;

static_assert(std::is_same_v<ByteSpan, std::span<const std::byte>>);
static_assert(std::is_same_v<MutableByteSpan, std::span<std::byte>>);

// Non-owning, per STD-0004. A borrow is trivially copyable and carries no
// destructor that could release what it views.
static_assert(std::is_trivially_copyable_v<ByteSpan>);
static_assert(std::is_trivially_copyable_v<MutableByteSpan>);
static_assert(std::is_trivially_destructible_v<ByteSpan>);
static_assert(std::is_trivially_destructible_v<MutableByteSpan>);

// The immutable spelling cannot be used to write, which is the property that
// makes naming it first and shorter a safety choice rather than a style one.
static_assert(std::is_const_v<ByteSpan::element_type>);
static_assert(!std::is_const_v<MutableByteSpan::element_type>);

} // namespace

TEST(Bytes, ViewsStorageWithoutOwningIt) {
    std::array<std::byte, 4> storage{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};

    const MutableByteSpan kMutableView{storage};
    kMutableView.front() = std::byte{9};

    const ByteSpan kView{storage};
    EXPECT_EQ(kView.size(), storage.size());
    EXPECT_EQ(kView.data(), storage.data());
    EXPECT_EQ(kView.front(), std::byte{9});
}

TEST(Bytes, ConvertsAMutableViewToAnImmutableOne) {
    std::array<std::byte, 2> storage{std::byte{7}, std::byte{8}};
    const MutableByteSpan kMutableView{storage};

    // The safe direction is implicit and the unsafe one does not exist. A test
    // cannot show the absence of a conversion, so what is asserted is that the
    // one that should exist does.
    const ByteSpan kView = kMutableView;
    EXPECT_EQ(kView.size(), 2U);
    EXPECT_EQ(kView.back(), std::byte{8});
}
