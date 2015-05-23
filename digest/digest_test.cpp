#include <iostream>
#include <stdlib.h>
#include <sstream>
#include "digest.h"

std::string sha1_str(const std::string& s)
{
    auto d = sha1_digest::calculate(s);
    std::ostringstream oss;
    oss << d;
    return oss.str();
}

void assert_equal(const std::string& a, const std::string& b)
{
    if (a == b) {
        return;
    }
    std::cerr << "\"" << a << "\" != \"" << b << "\"" << std::endl;
    abort();
}

int main()
{
    assert_equal(sha1_str("The quick brown fox jumps over the lazy dog"), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
    assert_equal(sha1_str("The quick brown fox jumps over the lazy cog"), "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3");
    assert_equal(sha1_str(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

