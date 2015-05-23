#include <iostream>
#include <stdlib.h>
#include <sstream>
#include "digest.h"

template<typename A, typename B>
void assert_equal(const A& a, const B& b)
{
    if (a == b) {
        return;
    }
    std::cerr << "\"" << a << "\" != \"" << b << "\"" << std::endl;
    abort();
}

int main()
{
    static const struct {
        std::string in;
        std::string hexres;
    } test_cases[] = {
        { "The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12" },
        { "The quick brown fox jumps over the lazy cog", "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3" },
        { "", "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
    };
    for (const auto& t : test_cases) {
        auto d = sha1_digest::calculate(t.in);
        assert_equal(d, sha1_digest(t.hexres));
        assert_equal(d != sha1_digest(t.hexres), false);
        assert_equal(t.hexres, d.str());
        std::ostringstream oss;
        oss << d;
        assert_equal(t.hexres, oss.str());
    }
}

