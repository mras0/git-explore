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

enum class object_type {
    blob, commit, tree
};

const char* object_type_string(object_type type)
{
    switch (type) {
    case object_type::blob:   return "blob";
    case object_type::commit: return "commit";
    case object_type::tree:   return "tree";
    }
    assert(false);
    throw std::runtime_error("Invalid object type " + std::to_string((unsigned)type));
}

std::istream& operator>>(std::istream& is, object_type& type) {
    std::string s;
    if (!(is >> s)) return is;
    for (unsigned i = 0; i <= static_cast<unsigned>(object_type::tree); ++i) {
        const auto ot = static_cast<object_type>(i);
        if (s == object_type_string(ot)) {
            type = ot;
            return is;
        }
    }
    throw std::runtime_error("Unknown object type \"" + s + "\"");
}

std::ostream& operator<<(std::ostream& os, object_type type) {
    return os << object_type_string(type);
}

class object {
public:
    object(object_type type, const std::string& data) : type_(type), data_(data) {}
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

object read_object(const std::string& base_dir, const sha1_digest& hash)
{
    std::ostringstream oss;
    const auto filename = base_dir + "objects/" + hash.str().insert(2, "/");
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
        if (c.find_attribute(attr)) {
            throw std::runtime_error("Duplicate attribute \"" + attr + "\" found in commit");
        }
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

int main(int argc, const char* argv[])
{
    std::string base_dir = argc >= 2 ? argv[1] : "";
    if (!base_dir.empty() && base_dir.back() != '/') base_dir += "/";
    base_dir += ".git/";
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
}
