#ifndef SHA1_DIGEST_H
#define SHA1_DIGEST_H

#include <stddef.h>
#include <assert.h>
#include <iosfwd>
#include <string>

class sha1_digest {
public:
    sha1_digest() {}
    sha1_digest(const std::string& s);

    static sha1_digest calculate(const void* bytes, size_t count);
    template<typename C>
    static sha1_digest calculate(const C& c) {
        static_assert(sizeof(*c.data()) == 1, "");
        return calculate(c.data(), c.size());
    }
    static sha1_digest read(std::istream& is);

    std::string str() const;

    unsigned char operator[](int index) const {
        assert(index >= 0 && index < (int)sizeof(digest_));
        return digest_[index];
    }

    int compare(const sha1_digest& rhs) const;

private:
    unsigned char digest_[20];
};

inline bool operator==(const sha1_digest& lhs, const sha1_digest& rhs) {
    return lhs.compare(rhs) == 0;
}

inline bool operator!=(const sha1_digest& lhs, const sha1_digest& rhs) {
    return !(lhs == rhs);
}

std::ostream& operator<<(std::ostream& os, const sha1_digest& d);

#endif
