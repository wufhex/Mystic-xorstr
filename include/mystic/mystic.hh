/**
 * @file mystic.hh
 * @brief A library for compile-time string encryption and decryption using constexpr computations.
 *
 * @author wufhex
 *
 * @note This library requires a C++17 compliant compiler.
 *
 * This library provides functionality for encrypting and decrypting strings at compile-time using constexpr computations.
 * It includes a template-based random number generator for key generation and a XOR-based encryption scheme.
 *
 * The encryption scheme involves dividing the string into 8-byte chunks, performing XOR operations with the keys and IV,
 * and then converting the encrypted chunks back into characters using AVX/SSE instructions.
 * 
 * It also adds junk code to mess with the disassembly and make it extremely nested to hide the 
 * decryption logic inside the code. Do not overuse MYSTIFY_BLOAT since it can heavily slow down 
 * performance and executable size, again if overused.
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

#ifndef __cplusplus
#error "C compiler detected! Please use a C++ compiler."
#endif

#include <array>
#include <string>
#include <sstream>
#include <vector>
#include <utility>
#include <functional>
#include <iomanip>
#include <cstdint>

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

#error "Unsupported architecture, Please define either AVX_AVAILABLE or SSE_AVAILABLE."
#endif

// ---------------VERSION----------------

#ifndef M_VER
#define M_VER_MAJ 2
#define M_VER_MIN 0
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
    }

    /**
     * @namespace Obfuscation
     * @brief Namespace containing functions with code that'll be added to the executable to mess with the disassembly.
     */
    namespace Obfuscation {

        /**
         * @brief Compile-time random key generator struct.
         * @tparam Seed The seed value for random generation.
         */
        template<uint64_t Seed>
        struct OSeed {
            static constexpr int key = Mystic::Random::Random<Seed, 42>::value % 1000;
        };

        /**
         * @brief Generate a pseudo-random seed from the current compile time.
         * @return A uint64_t value representing the seed.
         */
        INLINE_FUNCTION constexpr uint64_t GetSeed() noexcept {
            return (__TIME__[0] - '0') * 12000 + (__TIME__[1] - '0') * 1600 +
                   (__TIME__[3] - '0') * 300   + (__TIME__[4] - '0') * 30   +
                   (__TIME__[6] - '0') * 5     + (__TIME__[7] - '0');
        }

        /**
         * @brief Adds stack bloat by allocating and initializing a small volatile buffer.
         * @tparam N The (compile-time) size parameter for the buffer, capped at 8.
         */
        template<int N>
        INLINE_FUNCTION void StackBloat() noexcept {
            constexpr int SafeN = (N > 8 ? 8 : N);
            volatile uint64_t stackBuf[SafeN] = {};
            for (int i = 0; i < SafeN; ++i) {
                uint64_t val = (i * 0xE0FCEEU) ^ 0xDF3D4AEFU;
                stackBuf[i]  = __LoadFromRegister(val);
            }
            (void)stackBuf;
        }

        /**
         * @brief Adds control flow bloat by performing dummy volatile computations in a loop.
         * @tparam N The number of iterations for the dummy computation.
         */
        template<int N>
        INLINE_FUNCTION void ControlFlowBloat() noexcept {
            volatile int x = 0;
            for (int i = 0; i < N; ++i) {
                int val = ((i ^ x) & 1) ? (x + i) : (x - i);
                x = static_cast<int>(__LoadFromRegister(val));
            }
        }

        /**
         * @brief Adds lightweight logic noise using volatile variables and dummy register loads.
         * @tparam N The parameter to influence the dummy computation.
         */
        template<int N>
        INLINE_FUNCTION void LogicNoise() noexcept {
            volatile int      x = 0;
            volatile uint64_t a = 0xE7000FULL;
            volatile uint64_t b = 0x1DDFA0ULL;
            volatile uint64_t c = (a ^ b) + N;
            x = static_cast<int>(__LoadFromRegister(c));
            (void)x;
        }

        /**
         * @brief Adds AVX/SSE-based logic bloat using SIMD instructions and dummy register loads (variant A).
         * @tparam N The parameter to influence the dummy computation (not buffer size).
         */
        template<int N>
        INLINE_FUNCTION void LogicBloatAVXSSEA() noexcept {
            volatile int x = 0;
#if defined(AVX_AVAILABLE)
            alignas(32) uint64_t data[8] = {};
            __m256i vec = _mm256_set1_epi64x(0x6D24B3A58F7E1C90ULL);
            for (int i = 0; i < 8; i += 4) {
                _mm256_store_si256(reinterpret_cast<__m256i*>(&data[i]), vec);
                vec = _mm256_xor_si256(vec, _mm256_set1_epi64x(i ^ N));
            }
            volatile uint64_t sink = __LoadFromRegister(data[0]);
#elif defined(SSE_AVAILABLE)
            alignas(16) uint64_t data[4] = {};
            __m128i vec = _mm_set1_epi64x(0xF1297C4DEB3A5F08ULL);
            for (int i = 0; i < 4; i += 2) {
                _mm_store_si128(reinterpret_cast<__m128i*>(&data[i]), vec);
                vec = _mm_xor_si128(vec, _mm_set1_epi64x(i ^ N));
            }
            volatile uint64_t sink = __LoadFromRegister(data[0]);
#else
            constexpr int SafeN = (N > 8 ? 8 : N);
            volatile uint64_t data[SafeN] = {};
            for (int i = 0; i < SafeN; ++i) {
                data[i] = ((i * 0xB9C47E1032568ADFULL) ^ 0x2E5F9A8C7B0143D6ULL) + SafeN;
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
            volatile int x = 0;
#if defined(AVX_AVAILABLE)
            alignas(32) uint64_t arr[8] = {};
            __m256i v = _mm256_set1_epi64x(0x8A3E6B59247D1C0FULL);
            for (int i = 0; i < 8; i += 4) {
                v = _mm256_add_epi64(v, _mm256_set1_epi64x(i));
                _mm256_store_si256(reinterpret_cast<__m256i*>(&arr[i]), v);
            }
            volatile uint64_t sink = __LoadFromRegister(arr[7]);
#elif defined(SSE_AVAILABLE)
            alignas(16) uint64_t arr[4] = {};
            __m128i v = _mm_set1_epi64x(0xA10F9D2B7C43856EULL);
            for (int i = 0; i < 4; i += 2) {
                v = _mm_add_epi64(v, _mm_set1_epi64x(i));
                _mm_store_si128(reinterpret_cast<__m128i*>(&arr[i]), v);
            }
            volatile uint64_t sink = __LoadFromRegister(arr[3]);
#else
            constexpr int SafeN = (N > 8 ? 8 : N);
            volatile uint64_t arr[SafeN] = {};
                                    //    _ NICE
            uint64_t acc = 0xF3F3CACDE384F69ULL;
            for (int i = 0; i < SafeN; ++i) {
                acc ^= (i * 0x1EF4AULL);
                arr[i] = acc + i;
            }
            volatile uint64_t sink = __LoadFromRegister(arr[SafeN - 1]);
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
#else
            constexpr int SafeN = (N > 8 ? 8 : N);
            volatile uint64_t buf[SafeN] = {};
            bool toggle = false;
            for (int i = 0; i < SafeN; ++i) {
                if (toggle)
                    buf[i] = (i * 0xABCD1234ULL) ^ 0xDEADBEEFULL;
                else
                    buf[i] = (~(i * 0x1234ABCDULL)) + 0xCAFEBABEULL;
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

        /**
         * @brief Applies a sequence of bloat functions for obfuscation.
         * @tparam Key The key used to parameterize the bloat functions.
         */
        template<int Key>
        INLINE_FUNCTION void Apply() noexcept {
            constexpr int stackSize = (Key % 24) + 12;
            constexpr int cfSize    = (Key % 13) + 5;

            BloatRandomAVXSSE<Key>();
            StackBloat<stackSize>();
            ControlFlowBloat<cfSize>();
            StdBloat();
            LogicNoise<Key>();
            BloatRandomAVXSSE<Key>();
            __LoadFromRegister(0xFEA2C4F4830ULL);
        }
    } // namespace Obfuscation

    constexpr auto _keys_and_iv = Random::GenerateKeysAndIV();

    /**
     * @brief Encrypt a string using specified keys and IV.
     * @tparam N The size of the input string.
     * @param str The input string to be encrypted.
     * @return An array of uint64_t values representing the encrypted string.
     */
    template<size_t N>
    INLINE_FUNCTION constexpr auto __EncryptString(const char(&str)[N]) noexcept {
        std::array<uint64_t, (N + 7) / 8> encrypted{};

        constexpr uint64_t key1 = _keys_and_iv.data()[0];
        constexpr uint64_t key2 = _keys_and_iv.data()[1];
        constexpr uint64_t iv   = _keys_and_iv.data()[2];

        for (size_t i = 0; i < N; i += 8) {
            uint64_t chunk = 0;
            for (int j = 0; j < 8 && i + j < N; ++j) {
                chunk |= static_cast<uint64_t>(str[i + j]) << (j * 8);
            }

            chunk ^= (key1) ^ ((key2 << 3) & (key1 << 6)) ^ (iv ^ 0xFC11ULL);

            encrypted[i / 8] = chunk;
        }

        return encrypted;
    }

    /**
     * @brief Decrypt an encrypted string using specified keys and IV.
     * @tparam N The size of the encrypted data array.
     * @param encrypted The array of encrypted uint64_t values.
     * @return The decrypted string.
     */
    template<size_t N>
    INLINE_FUNCTION std::string __DecryptString(const std::array<uint64_t, (N + 7) / 8>& encrypted) noexcept {
        std::string decrypted;
#if defined(AVX_AVAILABLE)
        constexpr int ChunkSize = 32;
#elif defined(SSE_AVAILABLE)
        constexpr int ChunkSize = 16;
#endif

#if defined(AVX_AVAILABLE)
        __m256i key1 = _mm256_set1_epi64x(__LoadFromRegister(_keys_and_iv.data()[0]));
        __m256i key2 = _mm256_set1_epi64x(__LoadFromRegister(_keys_and_iv.data()[1]));
        __m256i iv   = _mm256_set1_epi64x(__LoadFromRegister(_keys_and_iv.data()[2]));

        for (size_t i = 0; i < N; i += ChunkSize) {
            __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&encrypted[i / 8]));
            chunk = _mm256_xor_si256(chunk, key1);

            __m256i k2_ls_3 = _mm256_slli_epi64(key2, 3);
            __m256i k1_ls_6 = _mm256_slli_epi64(key1, 6);
            __m256i kl3_kr6 = _mm256_and_si256(k2_ls_3, k1_ls_6);
            chunk = _mm256_xor_si256(chunk, kl3_kr6);

            __m256i k1_ls_i = _mm256_xor_si256(iv, _mm256_set1_epi64x(0xFC11ULL));
            chunk = _mm256_xor_si256(chunk, k1_ls_i);

            alignas(ChunkSize) uint8_t extractedBytes[ChunkSize];
            _mm256_store_si256(reinterpret_cast<__m256i*>(extractedBytes), chunk);

            for (int j = 0; j < ChunkSize && i + j < N; ++j) {
                decrypted += static_cast<char>(extractedBytes[j]);
            }
        }
#elif defined(SSE_AVAILABLE)
        __m128i key1 = _mm_set1_epi64x(__LoadFromRegister(_keys_and_iv.data()[0]));
        __m128i key2 = _mm_set1_epi64x(__LoadFromRegister(_keys_and_iv.data()[1]));
        __m128i iv   = _mm_set1_epi64x(__LoadFromRegister(_keys_and_iv.data()[2]));

        for (size_t i = 0; i < N; i += ChunkSize) {
            __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&encrypted[i / 8]));
            chunk = _mm_xor_si128(chunk, key1);

            __m128i k2_ls_3 = _mm_slli_epi64(key2, 3);
            __m128i k1_ls_6 = _mm_slli_epi64(key1, 6);
            __m128i kl3_kr6 = _mm_and_si128(k2_ls_3, k1_ls_6);
            chunk = _mm_xor_si128(chunk, kl3_kr6);

            __m128i k1_ls_i = _mm_xor_si128(iv, _mm_set1_epi64x(0xFC11ULL));
            chunk = _mm_xor_si128(chunk, k1_ls_i);

            alignas(ChunkSize) uint8_t extractedBytes[ChunkSize];
            _mm_store_si128(reinterpret_cast<__m128i*>(extractedBytes), chunk);

            for (int j = 0; j < ChunkSize && i + j < N; ++j) {
                decrypted += static_cast<char>(extractedBytes[j]);
            }
        }
#endif
        return decrypted;
    }

    /**
     * @brief A struct representing an encrypted string.
     * @tparam N The size of the encrypted data array.
     */
    template<size_t N>
    struct EncryptedString {
        std::array<uint64_t, (N + 7) / 8> data;

        /**
         * @brief Decrypt the encrypted string.
         * @return The decrypted string.
         */
        INLINE_FUNCTION std::string DecryptString(bool strip_null = true) const noexcept {
            std::string result = __DecryptString<N>(data);

            // Remove null terminator
            if (strip_null && !result.empty() && result.back() == '\0') {
                result.pop_back();
            }

            return result;
        }

        /**
         * @brief Get the encrypted data array.
         * @return Const reference to the encrypted data array.
         */
        INLINE_FUNCTION const std::array<uint64_t, (N + 7) / 8>& GetEncryptedData() const noexcept {
            return data;
        }
    };

    /**
     * @brief Encrypt a string and return an EncryptedString object.
     * @tparam N The size of the input string.
     * @param str The input string to be encrypted.
     * @return An EncryptedString object containing the encrypted data.
     */
    template<size_t N>
    INLINE_FUNCTION constexpr auto EncryptString(const char(&str)[N]) noexcept {
        return EncryptedString<N>{__EncryptString(str)};
    }
} // namespace Mystic

/**
 * @brief Macro to apply stack bloat, can be used outside the mystic library.
 */
#define M_APPLY_STACK_BLOAT Mystic::Obfuscation::Apply<Mystic::Obfuscation::OSeed<Mystic::Obfuscation::GetSeed()>::key>()

/**
 * @brief Macro to encrypt and decrypt a string at compile-time.
 * @param str The input string to be encrypted and decrypted.
 * @return The decrypted string.
 */
#define MYSTIFY_BLOAT(str) ([] { \
    M_APPLY_STACK_BLOAT; \
    constexpr auto encrypted = Mystic::EncryptString(str);   \
    M_APPLY_STACK_BLOAT; \
    return encrypted.DecryptString();                        \
}())

 /**
  * @brief Macro to encrypt and decrypt a string at compile-time keeping the null terminator.
  * @param str The input string to be encrypted and decrypted.
  * @return The decrypted string.
  */
#define MYSTIFY_KEEPNULL_BLOAT(str) ([] { \
    M_APPLY_STACK_BLOAT; \
    constexpr auto encrypted = Mystic::EncryptString(str);   \
    M_APPLY_STACK_BLOAT; \
    return encrypted.DecryptString(true);                    \
}())

/**
 * @brief Macro to encrypt and decrypt a string at compile-time without stack bloat.
 * @param str The input string to be encrypted and decrypted.
 * @return The decrypted string.
 */
#define MYSTIFY(str) ([] { \
    constexpr auto encrypted = Mystic::EncryptString(str);   \
    return encrypted.DecryptString();                        \
}())

/**
 * @brief Macro to encrypt and decrypt a string at compile-time keeping the null terminator, without stack bloat.
 * @param str The input string to be encrypted and decrypted.
 * @return The decrypted string.
 */
#define MYSTIFY_KEEPNULL(str) ([] { \
    constexpr auto encrypted = Mystic::EncryptString(str);   \
    return encrypted.DecryptString(true);                    \
}())
