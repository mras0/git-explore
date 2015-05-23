#include "digest.h"
#include "sha.h"
#include <istream>
#include <ostream>
#include <stdexcept>
#include <string.h>

namespace {

char hexchar(unsigned char n) {
    return n < 10 ? n + '0' : n + 'a' - 10;
}

unsigned char hexdigit(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else {
        return 255;
    }
}

} // unnamed namespace

sha1_digest::sha1_digest(const std::string& s) {
    if (s.size() != sizeof(digest_) * 2) {
        throw std::runtime_error("Invalid digest length of \"" + s + "\"");
    }
    for (unsigned i = 0; i < sizeof(digest_); ++i) {
        const auto a = hexdigit(s[i*2+0]);
        const auto b = hexdigit(s[i*2+1]);
        if (a > 15 || b > 15) {
            throw std::runtime_error("Invalid character(s) in digest \"" + s + "\"");
        }
        digest_[i] = a * 16 + b;
    }
}

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

sha1_digest sha1_digest::read(std::istream& is)
{
    sha1_digest res;
    if (!is.read((char*)&res.digest_, sizeof(res.digest_))) {
        throw std::runtime_error("Could not read sha1 digest");
    }
    return res;
}

int sha1_digest::compare(const sha1_digest& rhs) const
{
    return memcmp(digest_, rhs.digest_, sizeof(digest_));
}

std::string sha1_digest::str() const
{
    std::string r(sizeof(digest_)*2, '\0');
    for (unsigned i = 0; i < sizeof(digest_); ++i) {
        r[i*2+0] = hexchar(digest_[i]>>4);
        r[i*2+1] = hexchar(digest_[i]&0xf);
    }
    return r;
}

std::ostream& operator<<(std::ostream& os, const sha1_digest& d)
{
    return os << d.str();
}
