/* 
 * AVX_AVAILABLE M_ENABLE_BLOAT and M_ENABLE_BIGSTACK defined in Cmake file
 * You can also define it somewhere in the code and undefine them later if 
 * you want control over which MYSTIC calls inject junk code or enable big stack.
 * 
 *  Example:
 * -------------------------------------------------------
 *  #define M_ENABLE_BLOAT
 *  std::cout << MYSTIFY("Hello World!") << std::endl;
 *  #undef  M_ENABLE_BLOAT
 * -------------------------------------------------------
 * 
 */
#include <mystic/mystic.hh>
#include <iostream>

int main() {
    std::cout << MYSTIFY("Hello World!") << std::endl;
    // You can add M_APPLY_STACK_BLOAT wherever you want to make the code more obfuscated
    // But DO NOT overuse it, especially if M_ENABLE_BLOAT is defined.
    //
    // If you want more nested graphs but slower compile times, you can: 
    // 1. Add/remove DISPATCH and LABEL macros in mystic.hpp. Search for `MOD:` to find them.
    // 2. Add/remove StackBloat calls in mystic.hpp.
    M_APPLY_STACK_BLOAT;
    // Same for M_APPLY_BIG_STACK, using it once per function is enough to crash the stack.
    // If M_ENABLE_BIGSTACK is defined, MYSTIFY will automatically implement it in each decryption.
    M_APPLY_BIG_STACK;
    std::cout << MYSTIFY("Today is a beautiful day.") << std::endl;
    std::cout << MYSTIFY("And this executable is totally not obfuscated...") << std::endl;

    return 0;
}