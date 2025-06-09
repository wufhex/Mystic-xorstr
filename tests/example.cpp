#include <mystic/mystic.hh>
#include <iostream>

int main() {
    // Or just   MYSTIFY       to skip code obfuscation. 
    std::cout << MYSTIFY_BLOAT("Hello World!") << std::endl;
    std::cout << MYSTIFY_BLOAT("Today is a beautiful day.") << std::endl;
    std::cout << MYSTIFY_BLOAT("And this executable is totally not obfuscated...") << std::endl;

    return 0;
}