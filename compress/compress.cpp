#include "compress.h"

#include <zlib.h>
#include <stdexcept>
#include <istream>
#include <ostream>

namespace {

class zlib_exception : public std::runtime_error {
public:
    zlib_exception(const std::string& desc, int ret) : std::runtime_error(desc + " ret=" + std::to_string(ret)) {
    }
};

class zlib_stream {
public:
    zlib_stream() : stream_() {
        int ret = inflateInit(&stream_);
        if (ret != Z_OK) {
            throw zlib_exception("inflateInit failed", ret);
        }
    }

    ~zlib_stream() {
        inflateEnd(&stream_);
    }

    void decompress(std::ostream& dest, std::istream& source)
    {
        static constexpr size_t CHUNK = 16384;

        char in[CHUNK];
        char out[CHUNK];

        int ret;
        do {
            stream_.avail_in = source.readsome(in, sizeof(in));
            stream_.next_in  = reinterpret_cast<uint8_t*>(in);
            if (!source) {
                throw std::runtime_error("decompress: Error reading from source");
            }
            if (!stream_.avail_in) {
                break;
            }

            do {
                stream_.avail_out = sizeof(out);
                stream_.next_out  = reinterpret_cast<uint8_t*>(out);
                ret = inflate(&stream_, Z_NO_FLUSH);
                if (ret != Z_OK && ret != Z_STREAM_END) {
                    throw zlib_exception("inflate failed", ret);
                }

                dest.write(out, sizeof(out) - stream_.avail_out);
                if (!dest) {
                    throw std::runtime_error("decompress: Error writing to destination");
                }
            } while (stream_.avail_out == 0);

        } while (ret != Z_STREAM_END);
    }

protected:

    z_stream stream_;
};


} // unnamed namespace

void zlib_decompress(std::ostream& dest, std::istream& source)
{
    zlib_stream s;
    s.decompress(dest, source);
}
