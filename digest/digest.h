#ifndef SHA1_DIGEST_H
#define SHA1_DIGEST_H

#include <stddef.h>
#include <iosfwd>

class sha1_digest {
public:
    sha1_digest() {}

    static sha1_digest calculate(const void* bytes, size_t count);
    template<typename C>
    static sha1_digest calculate(const C& c) {
        static_assert(sizeof(*c.data()) == 1, "");
        return calculate(c.data(), c.size());
    }

    friend bool operator==(const sha1_digest& lhs, const sha1_digest& rhs);
    friend std::ostream& operator<<(std::ostream& os, const sha1_digest& d);
private:
    unsigned char digest_[20];
};

#endif
