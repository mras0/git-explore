#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <cassert>
#include <stdexcept>
#include <memory>
#include <algorithm>
#include <digest/digest.h>
#include <compress/compress.h>

void hexdump(std::ostream& os, const void* src, size_t len)
{
    auto s = reinterpret_cast<const uint8_t*>(src);
    for (size_t i = 0; i < len; i += 16) {
        size_t here = len - i;
        if (here > 16) here = 16;
        os << std::setw(4) << std::setfill('0') << i << ":" << std::hex;
        for (size_t j = i; j < i + here; ++j) {
            os << ' ' << std::setw(2) << unsigned(s[j]);
        }
        if (here < 16) for (size_t j = here; j < 16; ++j) os << "   ";
        os << "  ";
        for (size_t j = i; j < i + here; ++j) {
            const char c = s[j];
            os << (c >= 32 && c < 127 ? c : '.');
        }
        os << std::dec << std::setfill(' ');
        os << std::endl;
    }
}

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <vector>

std::vector<std::string> all_files_in_dir(const std::string& dir)
{
    std::unique_ptr<DIR, decltype(&::closedir)> dir_(opendir(dir.c_str()), &::closedir);
    if (!dir_) {
        return {};
    }

    std::vector<std::string> files;
    while (dirent* de = readdir(dir_.get())) {
        if (de->d_name[0] == '.') {
            continue;
        }
        const auto p = dir + "/" + de->d_name;
        struct stat st;
        if (stat(p.c_str(), &st) < 0) {
            throw std::runtime_error("stat('" + p + "') failed: " + strerror(errno));
        }
        if (!S_ISREG(st.st_mode)) {
            continue;
        }
        files.push_back(de->d_name);
    }
    return files;
}

enum class object_type : uint8_t {
	none = 0,
	commit = 1,
	tree = 2,
	blob = 3,
	tag = 4,
	ofs_delta = 6,
	ref_delta = 7,
};

const char* object_type_string(object_type type)
{
    switch (type) {
    case object_type::none:      return "none";
    case object_type::commit:    return "commit";
    case object_type::tree:      return "tree";
    case object_type::blob:      return "blob";
    case object_type::tag:       return "tag";
    case object_type::ofs_delta: return "ofs_delta";
    case object_type::ref_delta: return "ref_delta";
    }
    throw std::runtime_error("Invalid object type " + std::to_string((unsigned)type));
}

std::istream& operator>>(std::istream& is, object_type& type) {
    std::string s;
    if (!(is >> s)) return is;
#define CHECK_OBJTYPE(t) do { if (s == object_type_string(object_type::t)) { type = object_type::t; return is; } } while (0)
    CHECK_OBJTYPE(none);
    CHECK_OBJTYPE(commit);
    CHECK_OBJTYPE(tree);
    CHECK_OBJTYPE(blob);
    CHECK_OBJTYPE(tag);
    CHECK_OBJTYPE(ofs_delta);
    CHECK_OBJTYPE(ref_delta);
#undef CHECK_OBJTYPE
    throw std::runtime_error("Unknown object type \"" + s + "\"");
}

std::ostream& operator<<(std::ostream& os, object_type type) {
    return os << object_type_string(type);
}

class object {
public:
    object(object_type type=object_type::none, const std::string& data="") : type_(type), data_(data) {}
    virtual ~object() {}

    object_type type() const {
        return type_;
    }

    const std::string& str() const {
        return data_;
    }

    friend std::ostream& operator<<(std::ostream& os, const object& o) {
        return os << o.type_ << ' ' << o.data_.size() << "\n" << o.data_;
    }
private:
    object_type type_;
    std::string data_;
};

bool has_extension(const std::string& p, const std::string& ext)
{
    if (p.size() <= ext.size()) return false;
    if (p[p.size()-ext.size()-1] != '.') return false;
    return p.compare(p.size()-ext.size(), ext.size(), ext) == 0;
}

std::vector<std::string> all_packs(const std::string& pack_dir)
{
    std::vector<std::string> res;
    const auto files = all_files_in_dir(pack_dir);
    for (const auto& p : files) {
        if (has_extension(p, "idx")) {
            auto n = p.substr(0, p.size()-4);
            res.push_back(n);
        }
    }
    return res;
}

uint8_t read_u8(std::istream& is)
{
    unsigned char b;
    if (!is.read((char*)&b, 1)) {
        throw std::runtime_error("Error while reading");
    }
    return b;
}

uint32_t read_be_u32(std::istream& is)
{
    unsigned char bytes[4];
    if (!is.read((char*)bytes, sizeof(bytes))) {
        throw std::runtime_error("Error while reading");
    }
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | ((uint32_t)bytes[3]);
}

size_t read_delta_size(std::istream& is)
{
    size_t size = 0;
    uint8_t b = 0x80;
    for (unsigned shift = 0; b & 0x80; shift += 7) {
        assert(shift < sizeof(size)*8);
        b = read_u8(is);
        size |= size_t(b & 0x7f) << shift;
    }
    return size;
}

std::string apply_delta(const std::string& src, const std::string& delta) {
    std::istringstream d(delta);
    const size_t expected_src_size = read_delta_size(d);
    if (expected_src_size != src.size()) {
        throw std::runtime_error("Delta source size " + std::to_string(src.size()) + " != expected " + std::to_string(expected_src_size));
    }
    const size_t dst_size = read_delta_size(d);
    std::string res;
    while (d.rdbuf()->in_avail()) {
        const uint8_t b = read_u8(d);
        if (b == 0) {
            assert(false);
            throw std::runtime_error("Zero byte in delta");
        } else if (b & 0x80) {
            uint32_t offset = 0, size = 0;
            if (b & 0x01) offset |= read_u8(d);
            if (b & 0x02) offset |= ((uint32_t)read_u8(d))<<8;
            if (b & 0x04) offset |= ((uint32_t)read_u8(d))<<16;
            if (b & 0x08) offset |= ((uint32_t)read_u8(d))<<24;
            if (b & 0x10) size |= read_u8(d);
            if (b & 0x20) size |= ((uint32_t)read_u8(d))<<8;
            if (b & 0x40) size |= ((uint32_t)read_u8(d))<<16;
            if (!size) size = 1<<16;
            if (offset >= src.size() || (uint64_t)offset + size > src.size()) {
                std::ostringstream msg;
                msg << "offset " << offset << " size " << size << " out of range for src size " << src.size();
                throw std::runtime_error(msg.str());
            }
            res += src.substr(offset, size);
        } else {
            std::string tmp(b, '\0');
            if(!d.read(&tmp[0], b)) {
                throw std::runtime_error("Error applying delta");
            }
            res += tmp;
        }
    }
    assert(res.size() == dst_size);
    return res;
}

object read_object(const std::string& base_dir, const sha1_digest& hash);

object read_object_from_pack_file(const std::string& base_dir, const std::string& pack_filename, uint64_t offset)
{
    std::ifstream pack(pack_filename, std::ifstream::binary);
    if (!pack || !pack.is_open()) {
        throw std::runtime_error("Error opening " + pack_filename);
    }

    const auto sig = read_be_u32(pack);
    if (sig != 0x5041434b) { // PACK
        throw std::runtime_error(pack_filename + " has invalid PACK signature " + std::to_string(sig));
    }
    const auto ver = read_be_u32(pack);
    if (ver != 2) {
        throw std::runtime_error(pack_filename + " has invalid PACK version " + std::to_string(ver));
    }
    //const auto numobjs = read_be_u32(pack);

    pack.seekg(offset);
    uint8_t b = read_u8(pack);
    const auto type = static_cast<object_type>((b >> 4) & 7);
    size_t size = b&0xf;
    for (unsigned shift = 4; b & 0x80; shift += 7) {
        assert(shift < sizeof(size)*8);
        b = read_u8(pack);
        size |= size_t(b & 0x7f) << shift;
    }
    //std::cout << "Reading pack file entry of type " << type << " size " << size << std::endl;
    object delta_obj{};
    if (type == object_type::ofs_delta) {
        b = read_u8(pack);
        size_t offset_delta = b & 0x7f;
        while (b & 0x80) {
            ++offset_delta;
            offset_delta <<= 7;
            b = read_u8(pack);
            offset_delta |= b & 0x7f;
        }
        if (!offset_delta) {
            throw std::runtime_error("Invalid offset delta in " + pack_filename);
        }
        //std::cout << "offset_delta = " << offset_delta << std::endl;
        delta_obj = read_object_from_pack_file(base_dir, pack_filename, offset - offset_delta);
    } else if (type == object_type::ref_delta) {
        auto hash = sha1_digest::read(pack);
        //std::cout << "hash = " << hash << std::endl;
        delta_obj = read_object(base_dir, hash);
    } else if (type != object_type::commit && type != object_type::tree && type != object_type::blob) {
        std::ostringstream msg;
        msg << "Unsupported object type " << type << " in " << __func__;
        throw std::runtime_error(msg.str());
    }
    std::ostringstream oss;
    zlib_decompress(oss, pack);
    auto s = oss.str();
    if (s.size() != size) {
        std::ostringstream msg;
        msg << "Invalid uncompressed size " << s.size() << " expected " << size;
        throw std::runtime_error(msg.str());
    }
    if (delta_obj.type() != object_type::none) {
        assert(type == object_type::ofs_delta || type == object_type::ref_delta);
        return object{delta_obj.type(), apply_delta(delta_obj.str(), s)};
    }

    return object{type, s};
}

object read_object_from_pack(const std::string& base_dir, const sha1_digest& hash)
{
    const auto pack_dir = base_dir + "objects/pack/";
    for (const auto& p : all_packs(pack_dir)) {
        const auto idx_filename = pack_dir + p + ".idx";
        const auto pack_filename = pack_dir + p + ".pack";
        std::ifstream index(idx_filename, std::ifstream::binary);
        if (!index || !index.is_open()) {
            throw std::runtime_error("Error opening " + idx_filename);
        }

        uint32_t version = 1;
        uint32_t fan_table[256];
        auto magic = read_be_u32(index);
        if (magic == 0xff744f63) {
            version = read_be_u32(index);
        } else {
            fan_table[0] = magic;
        }
        for (int i = version == 1 ? 1 : 0; i < 256; ++i) {
            fan_table[i] = read_be_u32(index);
        }
        if (version != 2) {
            throw std::runtime_error("Invalid index file version " + std::to_string(version));
        }
        const auto sorted_name_index = 8+256*4;
        assert(index.tellg() == sorted_name_index);

        uint32_t low = 0;
        if (hash[0]) low = fan_table[hash[0]-1];
        uint32_t high = fan_table[hash[0]];

        while (low <= high) {
            const uint32_t mid = low + (high - low)/2;

            index.seekg(sorted_name_index + 20 * mid);
            const auto id = sha1_digest::read(index);
            //std::cout << "Looking for " << hash << " in [" << low << "; " << high << "] ";
            //std::cout << "mid= " << mid << " id = " << id << std::endl;

            const int c = hash.compare(id);
            if (c > 0) {
                low = mid + 1;
                if (!low) break;
            } else if (c < 0) {
                if (!mid) break;
                high = mid - 1;
            } else {
                //std::cout << "Found at index " << mid << std::endl;
                const auto offset_index = sorted_name_index + fan_table[255] * (20 + 4); // SHA + CRC for each entry
                index.seekg(offset_index + 4 * mid);
                const auto offset = read_be_u32(index);
                if (offset & 0x80000000) {
                    throw std::runtime_error("Offset in pack file with MSB set not supported (" + std::to_string(offset) + ")");
                }

                auto obj = read_object_from_pack_file(base_dir, pack_filename, offset);
                std::ostringstream digest_buf;
                digest_buf << obj.type() << ' ' << obj.str().size() << '\0' << obj.str();
                const auto d = sha1_digest::calculate(digest_buf.str());
                if (hash != d) {
                    std::ostringstream msg;
                    msg << "Digest mismatch for object " << hash << " - calculated digest: " << d << std::endl;
                    throw std::runtime_error(msg.str());
                }
                return obj;
            }
        }
    }
    std::ostringstream msg;
    msg << hash << " not found in any pack file";
    throw std::runtime_error(msg.str());
}

object read_object(const std::string& base_dir, const sha1_digest& hash)
{
    std::ostringstream oss;
    const auto filename = base_dir + "objects/" + hash.str().insert(2, "/");
    std::ifstream in(filename, std::ifstream::binary);
    if (!in || !in.is_open()) {
        // try pack directory
        return read_object_from_pack(base_dir, hash);
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
    object_type type;
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
    return object{type, res};
}

std::string read_line(const std::string& filename)
{
    std::ifstream in(filename);
    if (!in || !in.is_open()) {
        throw std::runtime_error("Error opening " + filename);
    }
    std::string line;
    if (!std::getline(in, line)) {
        throw std::runtime_error("Error reading line from " + filename);
    }
    assert(in.peek() == std::char_traits<char>::eof());
    return line;
}

object read_head(const std::string& base_dir)
{
    const auto filename = base_dir + "HEAD";
    auto line = read_line(filename);
    const std::string ref_prefix("ref: ");
    if (line.compare(0, ref_prefix.size(), ref_prefix) == 0) {
        auto ref_file = line.substr(ref_prefix.size());
        auto id = read_line(base_dir + ref_file);
        return read_object(base_dir, id);
    }
    throw std::runtime_error("Unexpected line in " + filename + " \"" + line + "\"");
}

#include <vector>
#include <utility>
struct commit {
    std::vector<std::pair<std::string, std::string>> attributes;
    std::string message;

    const std::string* find_attribute(const std::string& s) const {
        for (const auto& a : attributes) {
            if (a.first == s) {
                return &a.second;
            }
        }
        return nullptr;
    }

    const std::string& attribute(const std::string& attr) const {
        auto v = find_attribute(attr);
        if (!v) {
            throw std::runtime_error("Commit has no \""+attr+"\" attribute");
        }
        return *v;
    }
};

std::ostream& operator<<(std::ostream& os, const commit& c) {
    for (const auto& a : c.attributes) {
        os << a.first << " " << a.second << std::endl;
    }
    os << std::endl;
    os << c.message;
    return os;
}

commit parse_commit(const object& o)
{
    if (o.type() != object_type::commit) {
        std::ostringstream msg;
        msg << "Not a commit: " << o;
        throw std::runtime_error(msg.str());
    }

    commit c;
    std::istringstream iss(o.str());
    for (std::string line; std::getline(iss, line);) {
        if (line.empty()) {
           break;
        }
        const auto sp_pos = line.find_first_of(' ');
        if (sp_pos == 0 || sp_pos+1 == line.length() || sp_pos == std::string::npos) {
            throw std::runtime_error("Invalid line \"" + line + "\" encounted in commit");
        }
        auto attr = line.substr(0, sp_pos);
        auto val = line.substr(sp_pos+1);
        c.attributes.emplace_back(std::move(attr), std::move(val));
    }

    std::ostringstream oss;
    oss << iss.rdbuf();
    c.message = oss.str();
    return c;
}

struct tree {
    struct entry {
        std::string mode;
        std::string name;
        sha1_digest digest;
    };
    std::vector<entry> entries;
};

tree parse_tree(const object& o)
{
    if (o.type() != object_type::tree) {
        std::ostringstream msg;
        msg << "Not a tree: " << o;
        throw std::runtime_error(msg.str());
    }

    tree t;
    std::istringstream iss(o.str());
    while (iss.rdbuf()->in_avail()) {
        std::string mode, name;
        if (!(iss >> mode) || !std::getline(iss, name, '\0')) {
            throw std::runtime_error("Invalid tree");
        }
        t.entries.push_back({mode, name, sha1_digest::read(iss)});
    }

    return t;
}

void print_tree(std::ostream& os, const std::string& base_dir, const tree& t, const std::string& indent = "") {
    for (const auto& e : t.entries) {
        os << std::setw(6) << e.mode << " " << e.digest << " " << indent << e.name << std::endl;
        auto obj = read_object(base_dir, e.digest);
        if (obj.type() == object_type::tree) {
            print_tree(os, base_dir, parse_tree(obj), indent + "  ");
        } else if (obj.type() == object_type::blob) {
        } else {
            os << indent << "   " << obj.type() << std::endl;
            assert(false);
        }
    }
}

using file_list = std::vector<std::pair<std::string, std::string>>;

file_list all_files_in_tree(const std::string& base_dir, const tree& t, const std::string& path="") {
    file_list res;
    for (const auto& e : t.entries) {
        auto obj = read_object(base_dir, e.digest);
        if (obj.type() == object_type::tree) {
            auto subdir = all_files_in_tree(base_dir, parse_tree(obj), path+e.name+"/");
            res.insert(res.end(), subdir.begin(), subdir.end());
        } else if (obj.type() == object_type::blob) {
            res.push_back(make_pair(path+e.name, obj.str()));
        } else {
            assert(false);
        }
    }
    return res;
}

int main(int argc, const char* argv[])
{
    std::string base_dir = argc >= 2 ? argv[1] : "";
    if (!base_dir.empty() && base_dir.back() != '/') base_dir += "/";
    base_dir += ".git/";

    const auto tags_dir = base_dir + "refs/tags/";
    for (const auto& f : all_files_in_dir(tags_dir)) {
        std::cout << "TAG " << f << std::endl;
        std::cout << parse_commit(read_object(base_dir, read_line(tags_dir+f))) << std::endl;
    }
    std::cout << std::endl << std::endl;
    const auto heads_dir = base_dir + "refs/heads/";
    for (const auto& f : all_files_in_dir(heads_dir)) {
        std::cout << "HEAD " << f << std::endl;
        std::cout << parse_commit(read_object(base_dir, read_line(heads_dir+f))) << std::endl;
    }
    std::cout << std::endl << std::endl;

    auto head = parse_commit(read_head(base_dir));
    std::cout << head << std::endl;
    if (auto p = head.find_attribute("parent")) {
        std::string parent = *p;
        do {
            auto commit = parse_commit(read_object(base_dir, parent));
            std::cout << commit << std::endl;
            parent = "";
            if (auto pstr = commit.find_attribute("parent")) {
                parent = *pstr;
            }
        } while (parent.length());
    }
    std::cout << head.attribute("tree") << std::endl;
    auto t = parse_tree(read_object(base_dir, sha1_digest(head.attribute("tree"))));
    print_tree(std::cout, base_dir, t);
    for (const auto& f : all_files_in_tree(base_dir, t)) {
        std::cout << std::string(72,'*') << std::endl;
        std::cout << f.first << std::endl;
        std::cout << std::string(72,'*') << std::endl;
        std::cout << f.second << std::endl;
    }
}
