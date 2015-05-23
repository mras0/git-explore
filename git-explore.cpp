#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cassert>
#include <digest/digest.h>
#include <compress/compress.h>

#if 0
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
#endif

int main()
{
    std::ifstream in("../.git/objects/37/4ce9d0f408307ac48ec0866cc6dcae01512a5e", std::ifstream::binary);
    assert(in && in.is_open());
    std::ostringstream oss;
    zlib_decompress(oss, in);
    const auto s = oss.str();
    std::cout << s;
    std::cout << sha1_digest::calculate(s) << std::endl;
}
