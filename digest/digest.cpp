#include "digest.h"
#include "sha.h"
#include <ostream>
#include <string.h>

namespace {

char hexchar(unsigned char n) {
    return n < 10 ? n + '0' : n + 'a' - 10;
}

} // unnamed namespace

sha1_digest sha1_digest::calculate(const void* bytes, size_t count)
{
    sha1_digest res;
    static_assert(sizeof(res.digest_)==SHA1HashSize,"");

    SHA1Context context;
    SHA1Reset(&context);
    SHA1Input(&context, reinterpret_cast<const uint8_t*>(bytes), count);
    SHA1Result(&context, res.digest_);
    return res;
}

bool operator==(const sha1_digest& lhs, const sha1_digest& rhs)
{
    return memcmp(lhs.digest_, rhs.digest_, sizeof(lhs.digest_)) == 0;
}

std::ostream& operator<<(std::ostream& os, const sha1_digest& d)
{
    for (const auto& b : d.digest_) {
        os << hexchar(b>>4) << hexchar(b&0xf);
    }
    return os;
}
