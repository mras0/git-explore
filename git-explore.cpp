#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cassert>
#include <sha/sha.h>
#include <compress/compress.h>

void sha1(uint8_t digest[SHA1HashSize], const void* bytes, unsigned count)
{
    SHA1Context context;
    SHA1Reset(&context);
    SHA1Input(&context, reinterpret_cast<const uint8_t*>(bytes), count);
    SHA1Result(&context, digest);
}

std::string hex(const void* bytes, size_t count)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned i = 0; i < count; ++i) {
        auto b = reinterpret_cast<const uint8_t*>(bytes);
        oss << std::setw(2) << static_cast<unsigned>(b[i]);
    }
    return oss.str();
}

template<typename T, size_t sz>
std::string hex(const T (&arr)[sz])
{
    static_assert(sizeof(T)==1, "Untested");
    return hex(arr, sizeof(T) * sz);
}

void test_sha1()
{
    uint8_t digest[SHA1HashSize];
#define SHA1_STR_ARR(msg) sha1(digest, msg, sizeof(msg)-1)
    SHA1_STR_ARR("The quick brown fox jumps over the lazy dog");
    assert(hex(digest) == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
    SHA1_STR_ARR("The quick brown fox jumps over the lazy cog");
    assert(hex(digest) == "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3");
    SHA1_STR_ARR("");
    assert(hex(digest) == "da39a3ee5e6b4b0d3255bfef95601890afd80709");
#undef SHA1_STR_ARR
}

int main()
{
    test_sha1();
    std::ifstream in("../.git/objects/37/4ce9d0f408307ac48ec0866cc6dcae01512a5e", std::ifstream::binary);
    assert(in && in.is_open());
    std::ostringstream oss;
    zlib_decompress(oss, in);
    const auto s = oss.str();
    std::cout << s;
    uint8_t digest[SHA1HashSize];
    sha1(digest, s.data(), s.size());
    std::cout << hex(digest) << std::endl;
}
