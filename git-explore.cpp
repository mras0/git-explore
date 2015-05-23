#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cassert>
#include <stdexcept>
#include <memory>
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

class object {
public:
    virtual ~object() {}

    friend std::ostream& operator<<(std::ostream& os, const object& o) {
        o.do_out(os);
        return os;
    }
private:
    virtual void do_out(std::ostream& os) const = 0;
};

class blob : public object {
public:
    blob(const std::string& data) : data_(data) {}
    virtual ~blob() override {}

private:
    std::string data_;

    virtual void do_out(std::ostream& os) const override {
        os << data_;
    }
};

std::unique_ptr<object> read_object(const char* base_dir, const sha1_digest& hash)
{
    std::ostringstream oss;
    const auto filename = base_dir + hash.str().insert(2, "/");
    std::ifstream in(filename, std::ifstream::binary);
    if (!in || !in.is_open()) {
        throw std::runtime_error("Error opening " + filename);
    }
    zlib_decompress(oss, in);
    const auto s = oss.str();
    const auto d = sha1_digest::calculate(s);
    if (hash != d) {
        std::ostringstream msg;
        msg << "Digest mismatch for object " << hash << " - calculated digest: " << d << std::endl;
        throw std::runtime_error(msg.str());
    }
    const auto nul_pos = s.find_first_of('\0');
    if (nul_pos == std::string::npos) {
        throw std::runtime_error("Invalid git object " + hash.str() + " - No header found");
    }
    const auto header = s.substr(0, nul_pos);
    char space;
    std::string type;
    size_t size;
    if (!(std::istringstream(header) >> type >> std::noskipws >> space >> size) || space != ' ') {
        throw std::runtime_error("Invalid git object " + hash.str() + " - Header \"" + header + "\" invalid.");
    }
    const size_t actual_size = s.size() - nul_pos - 1;
    if (size != actual_size) {
        throw std::runtime_error("Invalid git object " + hash.str() + " - Expected size " + std::to_string(size) + " Actual size " + std::to_string(actual_size));
    }
    auto res = s.substr(nul_pos + 1);
    assert(res.size() == size);
    if (type == "blob") {
        return std::unique_ptr<object>{new blob{res}};
    }
    throw std::runtime_error("Git object " + hash.str() + " has unknown type \"" + type + "\"");
}

int main()
{
    std::cout << *read_object("../.git/objects/", sha1_digest("374ce9d0f408307ac48ec0866cc6dcae01512a5e"));
}
