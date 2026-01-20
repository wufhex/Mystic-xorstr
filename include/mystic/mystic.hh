/**
 * @file mystic.hh
 * @brief Compile-time string encryption/decryption library with advanced obfuscation and bloat features.
 *
 * @author wufhex
 *
 * @note Requires a C++17 compliant compiler.
 *
 * This library provides compile-time string encryption and decryption using constexpr computations,
 * supporting both AVX and SSE architectures. It features a template-based random number generator
 * for key/IV generation, and a multi-layered XOR-based encryption scheme.
 *
 * New features and improvements:
 * - Added a _MYSTIC_MINIMAL definition that strips any CRT related code, CRT-less string encryption is not implemented 
 *   as of today but it keeps features like bloating available for minimal environments like embedded systems.
 * - Multiple AVX/SSE-based logic bloat functions.
 * - Stack bloat and control flow flattening with opaque predicates and fake call indirection.
 * - Standard library bloat via dummy string/vector operations.
 * - Compile-time random selection of bloat variants for each use.
 * - Macros for easy application of stack bloat and decompiler crash logic.
 * - Improved compile-time key/IV generation using __TIME__.
 * - Decompiler crash stack logic for anti-reverse engineering.
 * - Configurable via macros (M_ENABLE_BLOAT, M_ENABLE_BIGSTACK).
 *
 * The encryption divides strings into 8-byte chunks, applies XOR with generated keys and IV,
 * and decrypts using AVX/SSE SIMD instructions for performance and obfuscation.
 *
 * The library is designed to make reverse engineering and static analysis significantly harder
 * by injecting junk code, complex control flow, and unpredictable bloat.
 *
 * --- MIT License ---
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#pragma once

#if defined(_MSC_VER)
#if !defined(__cplusplus) || (__cplusplus < 201703L)
#error "C++17 or higher is required. Use /std:c++17 and /Zc:__cplusplus with MSVC."
#endif
#else
static_assert(__cplusplus >= 201703L, "C++17 or higher is required");
#endif

#ifdef _MYSTIC_MINIMAL
#undef AVX_AVAILABLE
#undef SSE_AVAILABLE
#endif

#ifndef _MYSTIC_MINIMAL
#include <array>
#include <string>
#include <sstream>
#include <vector>
#include <utility>
#include <functional>
#include <iomanip>
#endif
#include <cstdint>

#ifdef _MYSTIC_MINIMAL
using size_t = uint64_t;
#endif

#ifndef _MYSTIC_MINIMAL
#if defined(AVX_AVAILABLE)
#include <immintrin.h>
#elif defined(SSE_AVAILABLE)
#include <emmintrin.h>
#else
// -------------------------------------------------------------------------------
// C operators support was removed due to problems with different compilers
// if you're intrested in it's implementation, open an issue or PR and I might
// implement it in the future. 
//
// Mystic v1 still has support for them tho I can't guarantee they'll work properly.
// -------------------------------------------------------------------------------

#error "Unsupported architecture, Please define either AVX_AVAILABLE or SSE_AVAILABLE, or define _MYSTIC_MINIMAL to strip CRT dependent functions."
#endif
#endif

// ---------------VERSION----------------

#ifndef M_VER
#define M_VER_MAJ 3
#define M_VER_MIN 1
#define M_VER_PTC 0

#define M_VER ( (M_VER_MAJ << 16) \
              | (M_VER_MIN << 8)  \
              | (M_VER_PTC))
#else
#error "Multiple version of Mystic have been included. M_VER already defined." 
#endif

// --------------------------------------

#ifdef _MSC_VER
#define INLINE_FUNCTION __forceinline
#else
#define INLINE_FUNCTION __attribute__((always_inline)) inline
#endif

/**
 * @brief Macro to apply stack bloat, can be used outside the mystic library.
 */
#define M_APPLY_STACK_BLOAT \
    Mystic::Obfuscation::Apply<Mystic::Obfuscation::GetSeed()>()


/**
 * @brief Macro to apply big stack. This macro will trigger a failure in the decompilation of some decompilers,
 * (ex. IDA) mostly when generating pseudo-C code.
 */
#define M_APPLY_BIG_STACK \
    Mystic::Obfuscation::DecompilerCrashStack<Mystic::Obfuscation::GetSeed()>()

/**
 * @namespace Mystic
 * @brief Namespace containing encryption and decryption utilities.
 * @note Yeah... good luck.
 */
namespace Mystic {
    /**
     * @brief Load a value from register using inline assembly (GCC) or volatile variable (MSVC).
     * @note This function is used to avoid compiler optimization.
     * @param value The value to load.
     * @return The loaded value.
     */
    INLINE_FUNCTION uint64_t __LoadFromRegister(uint64_t value) noexcept {
#if defined(__clang__) || defined(__GNUC__)
        asm("" : "=r"(value) : "0"(value) : "memory");
        return value;
#else
        volatile uint64_t reg = value;
        return reg;
#endif
    }
    
    // m_check is compared to 0, it'll always be true
    // because n^n is always 0. This will prevent the junk code from
    // executing at runtime but will still bloat the stack, because
    // the compiler will not optimize it out.
    template<int N>
    INLINE_FUNCTION bool __AlwaysTrue() {
        volatile int n = N;
        return (__LoadFromRegister(n) ^ __LoadFromRegister(n)) == 0;
    }

    /**
     * @namespace Random
     * @brief Namespace for random number generation utilities.
     */
    namespace Random {

        /**
         * @brief Template meta-programming structure to generate random numbers based on seed and index.
         * @tparam Seed The seed value for random number generation.
         * @tparam Index The index of the random number in the sequence.
         */
        template <uint64_t Seed, size_t Index>
        struct Random {
            static constexpr uint64_t value = 0xE4C7A1E07BAFULL * Random<Seed, Index - 1>::value % UINT64_MAX;
        };

        /**
         * @brief Specialization of Random structure for index 0, returning the seed itself.
         * @tparam Seed The seed value.
         */
        template <uint64_t Seed>
        struct Random<Seed, 0> {
            static constexpr uint64_t value = Seed;
        };

        /**
         * @brief Generate encryption keys and initialization vector (IV) using compile-time seed from time.
         * @return An array of three uint64_t values representing keys and IV.
         */
#ifndef _MYSTIC_MINIMAL
        INLINE_FUNCTION constexpr auto GenerateKeysAndIV() noexcept {
            constexpr uint64_t seed = [] {
                return (__TIME__[0] - '0') * 36000 + (__TIME__[1] - '0') * 3600 +
                       (__TIME__[3] - '0') * 600   + (__TIME__[4] - '0') * 60 +
                       (__TIME__[6] - '0') * 10    + (__TIME__[7] - '0');
                }();

                constexpr uint64_t key1 = Random<seed, 1>::value % UINT64_MAX;
                constexpr uint64_t key2 = Random<seed, 2>::value % UINT64_MAX;
                constexpr uint64_t iv   = Random<seed, 3>::value % UINT64_MAX;

                return std::array<uint64_t, 3>{ key1, key2, iv };
        }
#endif
    }

    /**
     * @namespace Obfuscation
     * @brief Namespace containing functions with code that'll be added to the executable to mess with the disassembly.
     */
    namespace Obfuscation {

        /**
         * @brief Generate a pseudo-random seed from the current compile time.
         * Once generated the seed gets cached to make the compilation faster.
         * @return A uint64_t value representing the seed.
         */
        constexpr uint64_t ParseSeedFromTime(const char* t) noexcept {
            return (t[0] - '0') * 12000ULL +
                   (t[1] - '0') * 1600ULL  +
                   (t[3] - '0') * 300ULL   +
                   (t[4] - '0') * 30ULL    +
                   (t[6] - '0') * 5ULL     +
                   (t[7] - '0');
        }

        constexpr uint64_t _cached_seed = ParseSeedFromTime(__TIME__);
        INLINE_FUNCTION constexpr uint64_t GetSeed() noexcept {
            return _cached_seed;
        }

        /**
         * @brief Adds significant stack bloat and complex control flow to hinder static analysis and decompilation.
         * This function creates a large, obfuscated control-flow graph consisting of 10 distinct labeled blocks,
         * each containing volatile operations and nested conditional statements designed to prevent compiler optimizations.
         * @tparam N Compile-time integer param used to initialize x.
         */
        template<int N>
        INLINE_FUNCTION void StackBloat() noexcept {
            volatile int      x       = N;
            volatile uint64_t dummy   = GetSeed();

            // Fake call indirection system to confuse call graph
            auto confuse_branch = [](int v) -> int {
                volatile uint64_t scramble = (v * (GetSeed() | 0x7F2E3D1C5A9B8F07UL)) ^ (GetSeed() | 0xC4D3E2F1A0B9C8D7ULL);
                return scramble % 21;
            };

            // Multi-hop jumps
            switch (confuse_branch(x)) {
            #define DISPATCH(i) \
                case i: goto hop1_##i; \
                hop1_##i: goto hop2_##i; \
                hop2_##i: goto label##i;

            // MOD: Dispatch
            DISPATCH(0)   DISPATCH(1)   DISPATCH(2)   DISPATCH(3)   DISPATCH(4)
            DISPATCH(5)

            #undef DISPATCH
            default: goto end;
            }

            // Label implementation — fake math, volatile ops, lambdas
            #define LABEL(i) \
                label##i: { \
                    volatile uint64_t x = (uint64_t)(i * 2); \
                    volatile uint64_t y = x + 1; \
                    volatile uint64_t z = y + 3; \
                    for (int j = 0; j < 5; ++j) { \
                        volatile uint64_t a = GetSeed() ^ (x + j); \
                        if ((a & 1) == 0) { \
                            if ((a ^ y) % 3 == 0) { \
                                if (((a + z) & 7) != 4) { \
                                    dummy ^= a & y; \
                                    dummy ^= __LoadFromRegister(a); \
                                } else { \
                                    dummy ^= x | z; \
                                } \
                            } else { \
                                dummy ^= y | a; \
                            } \
                        } else { \
                            if ((a | x) % 5 == 1) { \
                                if (((z ^ a) & 0xF) == 2) { \
                                    dummy ^= z & y; \
                                } else { \
                                    dummy ^= x | x; \
                                } \
                            } else { \
                                dummy ^= a | z; \
                            } \
                        } \
                    } \
                    \
                    dummy ^= __LoadFromRegister(x); \
                    dummy ^= __LoadFromRegister(y); \
                    dummy ^= __LoadFromRegister(z); \
                    goto end; \
                }

            // MOD: Label
            LABEL(0)   LABEL(1)   LABEL(2)   LABEL(3)   LABEL(4)
            LABEL(5)

            #undef LABEL
        end:;
            (void)dummy;
        }

        /**
         * @brief Adds AVX/SSE-based logic bloat using SIMD instructions and dummy register loads (variant A).
         * @tparam N The parameter to influence the dummy computation (not buffer size).
         */
#ifndef _MYSTIC_MINIMAL
        template<int N>
        INLINE_FUNCTION void LogicBloatAVXSSEA() noexcept {
            volatile  int      x    = 0;
            constexpr uint64_t val1 = GetSeed() ^ 0x6D24B3A58F7E1C90ULL;

#if defined(AVX_AVAILABLE)
            alignas(32) uint64_t data[8] = {};
            __m256i vec = _mm256_set1_epi64x(val1);
            for (int i = 0; i < 8; i += 4) {
                _mm256_store_si256(reinterpret_cast<__m256i*>(&data[i]), vec);
                vec = _mm256_xor_si256(vec, _mm256_set1_epi64x(i ^ N));
            }
            volatile uint64_t sink = __LoadFromRegister(data[0]);
#elif defined(SSE_AVAILABLE)
            alignas(16) uint64_t data[4] = {};
            __m128i vec = _mm_set1_epi64x(val1);
            for (int i = 0; i < 4; i += 2) {
                _mm_store_si128(reinterpret_cast<__m128i*>(&data[i]), vec);
                vec = _mm_xor_si128(vec, _mm_set1_epi64x(i ^ N));
            }
            volatile uint64_t sink = __LoadFromRegister(data[0]);
#endif
            x = static_cast<int>(__LoadFromRegister(sink));
            (void)x;
        }

        /**
         * @brief Adds AVX/SSE-based logic bloat using SIMD instructions and dummy register loads (variant B).
         * @tparam N The parameter to influence the dummy computation (not buffer size).
         */
        template<int N>
        INLINE_FUNCTION void LogicBloatAVXSSEB() noexcept {
            volatile  int      x    = 0;
            constexpr uint64_t val1 = GetSeed() ^ 0x8A3E6B59247D1C0FULL;

#if defined(AVX_AVAILABLE)
            alignas(32) uint64_t arr[8] = {};
            __m256i v = _mm256_set1_epi64x(val1);
            for (int i = 0; i < 8; i += 4) {
                v = _mm256_add_epi64(v, _mm256_set1_epi64x(i));
                _mm256_store_si256(reinterpret_cast<__m256i*>(&arr[i]), v);
            }
            volatile uint64_t sink = __LoadFromRegister(arr[7]);
#elif defined(SSE_AVAILABLE)
            alignas(16) uint64_t arr[4] = {};
            __m128i v = _mm_set1_epi64x(val1);
            for (int i = 0; i < 4; i += 2) {
                v = _mm_add_epi64(v, _mm_set1_epi64x(i));
                _mm_store_si128(reinterpret_cast<__m128i*>(&arr[i]), v);
            }
            volatile uint64_t sink = __LoadFromRegister(arr[3]);
#endif
            x = static_cast<int>(__LoadFromRegister(sink));
            (void)x;
        }

        /**
         * @brief Adds AVX/SSE-based logic bloat using SIMD instructions and dummy register loads (variant C).
         * @tparam N The parameter to influence the dummy computation (not buffer size).
         */
        template<int N>
        INLINE_FUNCTION void LogicBloatAVXSSEC() noexcept {
            volatile int x = 0;
#if defined(AVX_AVAILABLE)
            alignas(32) uint64_t buf[8] = {};
            __m256i v = _mm256_setzero_si256();
            int toggle = 0;
            for (int i = 0; i < 8; i += 4) {
                if (toggle) {
                    v = _mm256_or_si256(v, _mm256_set1_epi64x(i));
                } else {
                    v = _mm256_and_si256(v, _mm256_set1_epi64x(~i));
                }
                _mm256_store_si256(reinterpret_cast<__m256i*>(&buf[i]), v);
                toggle = !toggle;
            }
            volatile uint64_t sink = __LoadFromRegister(buf[0]);
#elif defined(SSE_AVAILABLE)
            alignas(16) uint64_t buf[4] = {};
            __m128i v = _mm_setzero_si128();
            int toggle = 0;
            for (int i = 0; i < 4; i += 2) {
                if (toggle) {
                    v = _mm_or_si128(v, _mm_set1_epi64x(i));
                } else {
                    v = _mm_and_si128(v, _mm_set1_epi64x(~i));
                }
                _mm_store_si128(reinterpret_cast<__m128i*>(&buf[i]), v);
                toggle = !toggle;
            }
            volatile uint64_t sink = __LoadFromRegister(buf[0]);
#endif
            x = static_cast<int>(__LoadFromRegister(sink));
            (void)x;
        }

        /**
         * @brief Adds standard library bloat by performing dummy string and vector operations.
         */
        INLINE_FUNCTION void StdBloat() noexcept {
            std::vector<std::pair<std::string, int>> data;
            std::stringstream ss;

            for (int i = 0; i < 16; ++i) {
                ss.str({});
                ss.clear();
                ss << std::hex << std::setw(4) << std::setfill('0') << (i * 1337);
                data.emplace_back(ss.str(), i);
            }

            std::function<int(const std::pair<std::string, int>&)> converter =
                std::bind([](const std::pair<std::string, int>& p) -> int {
                    std::stringstream inner;
                    inner << p.first;
                    int out;
                    inner >> std::hex >> out;
                    return out ^ (p.second << 2);
                }, std::placeholders::_1);

            volatile int dummy = 0;
            for (const auto& entry : data) {
                dummy += converter(entry) & 0xFF;
            }

            (void)dummy;
        }
#endif

        /**
         * @brief Helper to select a random bloat function at compile time.
         * @tparam Key The key used for selection.
         * @return An integer in [0,2] to select the bloat variant.
         */
        template<int Key>
        INLINE_FUNCTION constexpr int RandomSelector() noexcept {
            return Key % 3;
        }

        /**
         * @brief Randomly calls one of the AVX/SSE bloat functions based on the compile-time key.
         * @tparam Key The key used for selection.
         */
#ifndef _MYSTIC_MINIMAL
        template<int Key>
        INLINE_FUNCTION void BloatRandomAVXSSE() noexcept {
            constexpr int choice = RandomSelector<Key>();

            if constexpr (choice == 0) {
                LogicBloatAVXSSEA<(Key % 24) + 8>();
            } else if constexpr (choice == 1) {
                LogicBloatAVXSSEB<(Key % 21) + 4>();
            } else {
                LogicBloatAVXSSEC<(Key % 24) + 8>();
            }
        }
#endif

        /**
         * @brief Applies a sequence of bloat functions for obfuscation.
         * @tparam Key The key used to parameterize the bloat functions.
         */
        template<int Key>
        INLINE_FUNCTION void Apply() noexcept {
            if (__AlwaysTrue<Key>()) return;

            constexpr int stack_size = (Key % 24) + 12;
            constexpr uint64_t val1  = GetSeed() & 0xFEA2C4F4830ULL;

            StackBloat<stack_size>();
#ifndef _MYSTIC_MINIMAL
            BloatRandomAVXSSE<Key>();
#endif
            StackBloat<stack_size>();
#ifndef _MYSTIC_MINIMAL
            StdBloat();
#endif
            StackBloat<stack_size>();
#ifndef _MYSTIC_MINIMAL
            BloatRandomAVXSSE<Key>();
#endif
            StackBloat<stack_size>();

            __LoadFromRegister(val1);
        }

        /**
         * This function introduces a small amount of stack bloat and constructs an invalid function pointer cast.
         * This leads to decompilers failing to decompile the part of code where this function is called.
         *
         * @tparam Value Any numeric value.
         */
        template<int Value>
        INLINE_FUNCTION void DecompilerCrashStack() {
            if (__AlwaysTrue<Value>()) return;
            volatile uint64_t crash_buffer[2];

            using Fn = int(*)(int);
            Fn unreachable_fn = reinterpret_cast<Fn>(
                crash_buffer + ((Value % 0x400000) + 0x4000000)
            );
            __LoadFromRegister(
                reinterpret_cast<uint64_t>(unreachable_fn)
            );
        }
    } // namespace Obfuscation

#ifndef _MYSTIC_MINIMAL
    constexpr auto _keys_and_iv = Random::GenerateKeysAndIV();

    /**
     * @brief Encrypt a string using specified keys and IV.
     * @tparam N The size of the input string.
     * @param str The input string to be encrypted.
     * @return An array of uint64_t values representing the encrypted string.
     */
    template<typename CharT, size_t N>
    INLINE_FUNCTION constexpr auto __EncryptString(const CharT(&str)[N]) noexcept {
        constexpr size_t ChunkSize = 8 / sizeof(CharT);
        std::array<uint64_t, (N + ChunkSize - 1) / ChunkSize> encrypted{};

        constexpr uint64_t key1 = _keys_and_iv.data()[0];
        constexpr uint64_t key2 = _keys_and_iv.data()[1];
        constexpr uint64_t iv   = _keys_and_iv.data()[2];

        for (size_t i = 0; i < N; i += ChunkSize) {
            uint64_t chunk = 0;
            for (size_t j = 0; j < ChunkSize && i + j < N; ++j) { 
                chunk |= static_cast<uint64_t>(str[i + j]) << (j * sizeof(CharT) * 8);
            }

            chunk ^= (key1) ^ ((key2 << 3) & (key1 << 6)) ^ (iv ^ 0xFC11ULL);

            encrypted[i / ChunkSize] = chunk;
        }

        return encrypted;
    }

    /**
     * @brief Decrypt an encrypted string using specified keys and IV.
     * @tparam N The size of the encrypted data array.
     * @param encrypted The array of encrypted uint64_t values.
     * @return The decrypted string.
     */
    template<typename CharT, size_t N>
    INLINE_FUNCTION std::basic_string<CharT> __DecryptString(const std::array<uint64_t, (N + (8 / sizeof(CharT)) - 1) / (8 / sizeof(CharT))>& encrypted) noexcept {
#ifdef M_ENABLE_BIGSTACK
        M_APPLY_BIG_STACK;
#endif

        std::basic_string<CharT> decrypted;

        constexpr size_t BitsPerChar = sizeof(CharT) * 8;
        constexpr size_t CharsPerU64 = 8 / sizeof(CharT);
#if defined(AVX_AVAILABLE)
        constexpr size_t U64sPerSIMD = 4; // 256 bits / 64 bits per uint64
#elif defined(SSE_AVAILABLE)
        constexpr size_t U64sPerSIMD = 2; // 128 bits / 64 bits per uint64
#endif
        constexpr size_t CharsPerSIMD = CharsPerU64 * U64sPerSIMD;

#if defined(AVX_AVAILABLE)
        __m256i key1 = _mm256_set1_epi64x(__LoadFromRegister(_keys_and_iv.data()[0]));
        __m256i key2 = _mm256_set1_epi64x(__LoadFromRegister(_keys_and_iv.data()[1]));
        __m256i iv   = _mm256_set1_epi64x(__LoadFromRegister(_keys_and_iv.data()[2]));

        for (size_t i = 0; i < N; i += CharsPerSIMD) {
            __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&encrypted[i / CharsPerU64]));
            chunk = _mm256_xor_si256(chunk, key1);

#ifdef M_ENABLE_BLOAT
            M_APPLY_STACK_BLOAT;
#endif

            __m256i k2_ls_3 = _mm256_slli_epi64(key2, 3);
            __m256i k1_ls_6 = _mm256_slli_epi64(key1, 6);
            __m256i kl3_kr6 = _mm256_and_si256(k2_ls_3, k1_ls_6);
            chunk = _mm256_xor_si256(chunk, kl3_kr6);

            __m256i k1_ls_i = _mm256_xor_si256(iv, _mm256_set1_epi64x(0xFC11ULL));
            chunk = _mm256_xor_si256(chunk, k1_ls_i);

#ifdef M_ENABLE_BLOAT
            M_APPLY_STACK_BLOAT;
#endif

            alignas(32) uint64_t out[U64sPerSIMD];
            _mm256_store_si256(reinterpret_cast<__m256i*>(out), chunk);

            for (size_t u = 0; u < U64sPerSIMD; ++u) {
                uint64_t v = out[u];
                for (size_t c = 0; c < CharsPerU64; ++c) {
                    size_t idx = i + u * CharsPerU64 + c;
                    if (idx < N) {
                        decrypted += static_cast<CharT>((v >> (c * BitsPerChar)) & ((1ULL << BitsPerChar) - 1));
                    }
                }
            }
        }

#elif defined(SSE_AVAILABLE)
        __m128i key1 = _mm_set1_epi64x(__LoadFromRegister(_keys_and_iv.data()[0]));
        __m128i key2 = _mm_set1_epi64x(__LoadFromRegister(_keys_and_iv.data()[1]));
        __m128i iv   = _mm_set1_epi64x(__LoadFromRegister(_keys_and_iv.data()[2]));

        for (size_t i = 0; i < N; i += CharsPerSIMD) {
            __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&encrypted[i / CharsPerU64]));
            chunk = _mm_xor_si128(chunk, key1);

#ifdef M_ENABLE_BLOAT
            M_APPLY_STACK_BLOAT;
#endif

            __m128i k2_ls_3 = _mm_slli_epi64(key2, 3);
            __m128i k1_ls_6 = _mm_slli_epi64(key1, 6);
            __m128i kl3_kr6 = _mm_and_si128(k2_ls_3, k1_ls_6);
            chunk = _mm_xor_si128(chunk, kl3_kr6);

            __m128i k1_ls_i = _mm_xor_si128(iv, _mm_set1_epi64x(0xFC11ULL));
            chunk = _mm_xor_si128(chunk, k1_ls_i);

#ifdef M_ENABLE_BLOAT
            M_APPLY_STACK_BLOAT;
#endif

            alignas(16) uint64_t out[U64sPerSIMD];
            _mm_store_si128(reinterpret_cast<__m128i*>(out), chunk);

            for (size_t u = 0; u < U64sPerSIMD; ++u) {
                uint64_t v = out[u];
                for (size_t c = 0; c < CharsPerU64; ++c) {
                    size_t idx = i + u * CharsPerU64 + c;
                    if (idx < N) {
                        decrypted += static_cast<CharT>((v >> (c * BitsPerChar)) & ((1ULL << BitsPerChar) - 1));
                    }
                }
            }
        }
#endif // SSE_AVAILABLE / AVX_AVAILABLE

        return decrypted;
    }

    /**
     * @brief A struct representing an encrypted string.
     * @tparam N The size of the encrypted data array.
     */
    template<typename CharT, size_t N>
    struct EncryptedString {
        constexpr static size_t ChunkSize = 8 / sizeof(CharT);
        std::array<uint64_t, (N + ChunkSize - 1) / ChunkSize> data;

        /**
         * @brief Decrypt the encrypted string.
         * @return The decrypted string.
         */
        INLINE_FUNCTION std::basic_string<CharT> DecryptString(bool strip_null = true) const noexcept {
            std::basic_string<CharT> result = __DecryptString<CharT, N>(data);

            if (strip_null && !result.empty() && result.back() == CharT('\0')) {
                result.pop_back();
            }

            return result;
        }

        /**
         * @brief Get the encrypted data array.
         * @return Const reference to the encrypted data array.
         */
        INLINE_FUNCTION const std::array<uint64_t, (N + ChunkSize - 1) / ChunkSize>& GetEncryptedData() const noexcept {
            return data;
        }
    };

    /**
     * @brief Encrypt a string and return an EncryptedString object.
     * @tparam N The size of the input string.
     * @param str The input string to be encrypted.
     * @return An EncryptedString object containing the encrypted data.
     */
    template<typename CharT, size_t N>
    INLINE_FUNCTION constexpr auto EncryptString(const CharT(&str)[N]) noexcept {
        return EncryptedString<CharT, N>{__EncryptString<CharT, N>(str)};
    }
#endif
} // namespace Mystic

#ifndef _MYSTIC_MINIMAL
/**
 * @brief Macro to encrypt and decrypt a char string at compile-time.
 * @param str The input string to be encrypted and decrypted.
 * @return The decrypted std::string.
 */
#define MYSTIFY(str) ([] { \
    constexpr auto encrypted = Mystic::EncryptString(str); \
    return encrypted.DecryptString(); \
}())

/**
 * @brief Macro to encrypt and decrypt a char string at compile-time keeping the null terminator.
 * @param str The input string to be encrypted and decrypted.
 * @return The decrypted std::string including '\0'.
 */
#define MYSTIFY_KEEPNULL(str) ([] { \
    constexpr auto encrypted = Mystic::EncryptString(str); \
    return encrypted.DecryptString(false); \
}())

/**
 * @brief Macro to encrypt and decrypt a wchar_t string at compile-time.
 * @param wstr The input wide string to be encrypted and decrypted.
 * @return The decrypted std::wstring.
 */
#define MYSTIFYW(wstr) ([] { \
    constexpr auto encrypted = Mystic::EncryptString(wstr); \
    return encrypted.DecryptString(); \
}())

/**
 * @brief Macro to encrypt and decrypt a wchar_t string at compile-time keeping the null terminator.
 * @param wstr The input wide string to be encrypted and decrypted.
 * @return The decrypted std::wstring including L'\0'.
 */
#define MYSTIFYW_KEEPNULL(wstr) ([] { \
    constexpr auto encrypted = Mystic::EncryptString(wstr); \
    return encrypted.DecryptString(false); \
}())

/**
 * @deprecated Use MYSTIFY
 */
#define MYSTIFY_BLOAT(str)          MYSTIFY(str)

/**
 * @deprecated Use MYSTIFY_KEEPNULL
 */
#define MYSTIFY_BLOAT_KEEPNULL(str) MYSTIFY_KEEPNULL(str)
#endif