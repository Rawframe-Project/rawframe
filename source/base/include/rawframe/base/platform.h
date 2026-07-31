#pragma once

// Compiler and architecture detection, and the debugger-break primitive.
//
// ADR-0075 class 4. Base needs conditional compilation for exactly one thing at
// this gate, and SPEC-0046 fixes the surface to these three names. A detection
// macro lands when a facility needs it, not before.

// Everything published here is a macro, and the analyzer's standing advice is to
// prefer a constexpr constant or a function instead. Neither can be used: a
// constant cannot participate in `#if`, which is the only place these three
// answers are needed, and a debugger break must expand at the call site to stop
// there rather than inside a callee.
// NOLINTBEGIN(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum)

#if defined(_MSC_VER) && !defined(__clang__)
/// Defined to 1 under the MSVC frontend. Exactly one compiler macro is defined.
#define RAWFRAME_COMPILER_MSVC 1
#elifdef __clang__
/// Defined to 1 under the Clang frontend, including clang-cl.
#define RAWFRAME_COMPILER_CLANG 1
#else
// ADR-0008 makes the compiler a pinned platform contract. A silent fallback here
// would be a C++20-style fallback path by another name, so an unrecognised
// compiler fails the translation unit instead of selecting a default.
#error "Rawframe requires a pinned Clang or MSVC frontend; this compiler is unsupported."
#endif

#if defined(__x86_64__) || defined(_M_X64)
/// Defined to 1 on the one admitted architecture.
#define RAWFRAME_ARCH_X86_64 1
#else
#error "Rawframe supports only the x86-64 architecture; this target is unsupported."
#endif

#ifdef RAWFRAME_COMPILER_MSVC
extern "C" void __debugbreak(void);
/// Traps to an attached debugger and returns when none is attached. It is not a
/// termination primitive and must not be used as one.
#define RAWFRAME_DEBUG_BREAK() __debugbreak()
#else
/// Traps to an attached debugger and returns when none is attached. It is not a
/// termination primitive and must not be used as one.
#define RAWFRAME_DEBUG_BREAK() __builtin_debugtrap()
#endif

// NOLINTEND(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum)
