/**
 * @file mystic.hh
 * @brief A library for compile-time string encryption and decryption using constexpr computations.
 *
 * @author WolfHex
 *
 * @note This library requires a C++17 compliant compiler.
 *
 * This library provides functionality for encrypting and decrypting strings at compile-time using constexpr computations.
 * It includes a template-based random number generator for key generation and a XOR-based encryption scheme.
 *
 * The encryption scheme involves dividing the string into 8-byte chunks, performing XOR operations with the keys and IV,
 * and then converting the encrypted chunks back into characters using AVX/SSE instructions.
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
#include <array>
#include <string>
#include <cstdint>

#ifdef _MSC_VER
#define INLINE_FUNCTION __forceinline
#else
#define INLINE_FUNCTION __attribute__((always_inline)) inline
#endif

#if defined(AVX_AVAILABLE)
#include <immintrin.h>
#elif defined(SSE_AVAILABLE)
#include <emmintrin.h>
#else
#define UNSUPPORTED_MSG "Unsupported Architecture, Using C Operators - Supported: (SIMD AVX/SSE)"
#if _MSC_VER
#pragma message(UNSUPPORTED_MSG)
#else
#warning(UNSUPPORTED_MSG)
#endif
#endif

/**
 * @namespace Mystic
 * @brief Namespace containing encryption and decryption utilities.
 */
    namespace Mystic {

    /**
     * @namespace Random
     * @brief Nested namespace for random number generation utilities.
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
                    (__TIME__[3] - '0') * 600 + (__TIME__[4] - '0') * 60 +
                    (__TIME__[6] - '0') * 10 + (__TIME__[7] - '0');
                }();

                constexpr uint64_t key1 = Random<seed, 1>::value % UINT64_MAX;
                constexpr uint64_t key2 = Random<seed, 2>::value % UINT64_MAX;
                constexpr uint64_t iv = Random<seed, 3>::value % UINT64_MAX;

                return std::array<uint64_t, 3>{key1, key2, iv};
        }
    }

    constexpr auto keys_and_iv = Random::GenerateKeysAndIV();

    /**
     * @brief Load a value from register using inline assembly or volatile variable.
     * @param value The value to load.
     * @return The loaded value.
     */
    INLINE_FUNCTION uint64_t __LoadFromRegister(uint64_t value) noexcept {
#if defined(__clang__) || defined(__GNUC__)
        asm("" : "=r"(value) : "0"(value) : );
        return value;
#else
        volatile uint64_t reg = value;
        return reg;
#endif
    }

    /**
     * @brief Encrypt a string using specified keys and IV.
     * @tparam N The size of the input string.
     * @param str The input string to be encrypted.
     * @return An array of uint64_t values representing the encrypted string.
     */
    template<size_t N>
    INLINE_FUNCTION constexpr auto __EncryptString(const char(&str)[N]) noexcept {
        std::array<uint64_t, (N + 7) / 8> encrypted{};

        constexpr uint64_t key1 = keys_and_iv.data()[0];
        constexpr uint64_t key2 = keys_and_iv.data()[1];
        constexpr uint64_t iv = keys_and_iv.data()[2];

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
        __m256i key1 = _mm256_set1_epi64x(__LoadFromRegister(keys_and_iv.data()[0]));
        __m256i key2 = _mm256_set1_epi64x(__LoadFromRegister(keys_and_iv.data()[1]));
        __m256i iv = _mm256_set1_epi64x(__LoadFromRegister(keys_and_iv.data()[2]));

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
        __m128i key1 = _mm_set1_epi64x(__LoadFromRegister(keys_and_iv.data()[0]));
        __m128i key2 = _mm_set1_epi64x(__LoadFromRegister(keys_and_iv.data()[1]));
        __m128i iv = _mm_set1_epi64x(__LoadFromRegister(keys_and_iv.data()[2]));

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
#else
        constexpr uint64_t key1 = __LoadFromRegister(keys_and_iv.data()[0]);
        constexpr uint64_t key2 = __LoadFromRegister(keys_and_iv.data()[1]);
        constexpr uint64_t iv = __LoadFromRegister(keys_and_iv.data()[2]);

        for (size_t i = 0; i < N; i += 8) {
            uint64_t chunk = encrypted[i / 8];

            chunk ^= (key1) ^ ((key2 << 3) & (key1 << 6)) ^ (iv ^ 0xFC11ULL);

            for (int j = 0; j < 8 && i + j < N; ++j) {
                decrypted += static_cast<char>((chunk >> (j * 8)) & 0xFF);
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
 * @brief Macro to encrypt and decrypt a string at compile-time.
 * @param str The input string to be encrypted and decrypted.
 * @return The decrypted string.
 */
#define MYSTIFY(str) ([] { \
    constexpr auto encrypted = Mystic::EncryptString(str); \
    return encrypted.DecryptString(); \
}())

 /**
  * @brief Macro to encrypt and decrypt a string at compile-time keeping the null terminator.
  * @param str The input string to be encrypted and decrypted.
  * @return The decrypted string.
  */
#define MYSTIFY_KEEPNULL(str) ([] { \
    constexpr auto encrypted = Mystic::EncryptString(str); \
    return encrypted.DecryptString(true); \
}())