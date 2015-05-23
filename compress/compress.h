#ifndef COMPRESS_COMPRESS_H
#define COMPRESS_COMPRESS_H
#include <iosfwd>

void zlib_decompress(std::ostream& dest, std::istream& source);

#endif
