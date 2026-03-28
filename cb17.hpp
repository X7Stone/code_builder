// C++ Project building system
// Requires C++17

// Pavlygin Danil 2026

//Done:
//  Append
//  Directory and source-file validation
//  Environmantal variable getter
//  Args parsing

// Todo:
//  Compiler detection
//  Library linking
//  Concurrent compilation
//  package-config
//  Get script .cpp name out of the name of executable

#ifndef CODE_BUILDER_INCLUDE_HPP
#define CODE_BUILDER_INCLUDE_HPP

#define _CRT_SECURE_NO_WARNINGS

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

// Type validation helpers for C++17

#define CONCEPT(name, impl_name, condition, message)                \
    template<typename ...Ts>                                        \
    struct impl_name {                                              \
        static constexpr bool test = (condition<Ts>::value && ...); \
        using type = typename std::enable_if<test, int>::type;      \
    };                                      \
    template<typename ...Ts>                                        \
    using name = typename impl_name<Ts...>::type;

template<typename T>
struct string_rep_cond : std::is_constructible<std::string, T> {};

CONCEPT(string_rep, string_rep_impl, string_rep_cond, "The type must be string or const char*")

template<typename T>
struct path_rep_cond : std::is_constructible<std::filesystem::path, T> {};

CONCEPT(path_rep, path_rep_impl, path_rep_cond, "The type must be path")

// SHA256 implementation
// Copyright(c) 2010 Ilya O.Levin, http://www.literatecode.com

extern "C"
{
typedef struct {
    uint32_t buf[16];
    uint32_t hash[8];
    uint32_t len[2];
} sha256_context;

void sha256_init(sha256_context* ctx);
void sha256_hash(sha256_context* ctx, uint8_t* data, uint32_t len);
void sha256_done(sha256_context* ctx, uint8_t* hash);

#define RL(x,n)   (((x) << n) | ((x) >> (32 - n)))
#define RR(x,n)   (((x) >> n) | ((x) << (32 - n)))

#define S0(x)  (RR((x), 2) ^ RR((x),13) ^ RR((x),22))
#define S1(x)  (RR((x), 6) ^ RR((x),11) ^ RR((x),25))
#define G0(x)  (RR((x), 7) ^ RR((x),18) ^ ((x) >> 3))
#define G1(x)  (RR((x),17) ^ RR((x),19) ^ ((x) >> 10))

const uint32_t K[64] = {
     0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
     0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
     0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
     0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void _bswapw(uint32_t *p, uint32_t i)
{
    while (i--) p[i] = (RR(p[i],24) & 0x00ff00ff) | (RR(p[i],8) & 0xff00ff00);

} /* _bswapw */

void _rtrf(uint32_t *b, uint32_t *p, uint32_t i, uint32_t j)
{
    #define B(x, y) b[(x-y) & 7]
    #define P(x, y) p[(x+y) & 15]

    B(7,i) += (j ? (p[i & 15] += G1(P(i,14)) + P(i,9) + G0(P(i,1))) : p[i & 15])
              + K[i+j] + S1(B(4,i))
              + (B(6,i) ^ (B(4,i) & (B(5,i) ^ B(6,i))));
    B(3,i) += B(7,i);
    B(7,i) += S0(B(0,i)) + ( (B(0,i) & B(1,i)) | (B(2,i) & (B(0,i) ^ B(1,i))) );

    #undef P
    #undef B
} /* _rtrf */

void _hash(sha256_context *ctx)
{
    uint32_t b[8], *p, j;

    b[0] = ctx->hash[0]; b[1] = ctx->hash[1]; b[2] = ctx->hash[2];
    b[3] = ctx->hash[3]; b[4] = ctx->hash[4]; b[5] = ctx->hash[5];
    b[6] = ctx->hash[6]; b[7] = ctx->hash[7];

    for (p = ctx->buf, j = 0; j < 64; j += 16)
        _rtrf(b, p,  0, j), _rtrf(b, p,  1, j), _rtrf(b, p,  2, j),
        _rtrf(b, p,  3, j), _rtrf(b, p,  4, j), _rtrf(b, p,  5, j),
        _rtrf(b, p,  6, j), _rtrf(b, p,  7, j), _rtrf(b, p,  8, j),
        _rtrf(b, p,  9, j), _rtrf(b, p, 10, j), _rtrf(b, p, 11, j),
        _rtrf(b, p, 12, j), _rtrf(b, p, 13, j), _rtrf(b, p, 14, j),
        _rtrf(b, p, 15, j);

    ctx->hash[0] += b[0]; ctx->hash[1] += b[1]; ctx->hash[2] += b[2];
    ctx->hash[3] += b[3]; ctx->hash[4] += b[4]; ctx->hash[5] += b[5];
    ctx->hash[6] += b[6]; ctx->hash[7] += b[7];

} /* _hash */

void sha256_init(sha256_context *ctx)
{
    ctx->len[0] = ctx->len[1] = 0;
    ctx->hash[0] = 0x6a09e667; ctx->hash[1] = 0xbb67ae85;
    ctx->hash[2] = 0x3c6ef372; ctx->hash[3] = 0xa54ff53a;
    ctx->hash[4] = 0x510e527f; ctx->hash[5] = 0x9b05688c;
    ctx->hash[6] = 0x1f83d9ab; ctx->hash[7] = 0x5be0cd19;

} /* sha256_init */

void sha256_hash(sha256_context *ctx, uint8_t *dat, uint32_t sz)
{
    //register uint32_t i = ctx->len[0] & 63, l, j;
    uint32_t i = ctx->len[0] & 63, l, j;

    if ((ctx->len[0] += sz) < sz)  ++(ctx->len[1]);

    for (j = 0, l = 64-i; sz >= l; j += l, sz -= l, l = 64, i = 0)
    {
        memcpy((char *)ctx->buf + i, &dat[j], l);
        _bswapw(ctx->buf, 16 );
        _hash(ctx);
    }
    memcpy((char *)ctx->buf + i, &dat[j], sz);

} /* _hash */

void sha256_done(sha256_context *ctx, uint8_t *buf)
{
    uint32_t i = (uint32_t)(ctx->len[0] & 63), j = ((~i) & 3) << 3;

    _bswapw(ctx->buf, (i + 3) >> 2);

    ctx->buf[i >> 2] &= 0xffffff80 << j;  /* add padding */
    ctx->buf[i >> 2] |= 0x00000080 << j;

    if (i < 56) i = (i >> 2) + 1;
       else ctx->buf[15] ^= (i < 60) ? ctx->buf[15] : 0, _hash(ctx), i = 0;

    while (i < 14) ctx->buf[i++] = 0;

    ctx->buf[14] = (ctx->len[1] << 3)|(ctx->len[0] >> 29); /* add length */
    ctx->buf[15] = ctx->len[0] << 3;

    _hash(ctx);

    for (i = 0; i < 32; i++)
       ctx->buf[i % 16] = 0, /* may remove this line in case of a DIY cleanup */
       buf[i] = (uint8_t)(ctx->hash[i >> 2] >> ((~i & 3) << 3));

} /* sha256_done */
} // extern "C"

namespace cb
{
namespace fs = std::filesystem;
using path = fs::path;

// Auto-detected source-file extensions
const std::vector<std::string> SourceExtensions{
    ".c",
    ".cpp",
    ".cxx"
};

// Auto-detected header-file extensions
const std::vector<std::string> HeaderExtensions{
    ".h",
    ".hpp"
};

// Interface ----------------------------------------------------------------------------

// [1] Args parser

// Searches for key substr in strings
// Removes the item where key is found (only first)
// Return example: arg = "--target=win64", key = "--target=" -> returns "win64"
template<typename StringRange>
std::optional<std::string> search_and_erase(StringRange& strings, const std::string& key);

class parser {
public:
    parser(int argc, char** argv);
    auto begin() const;
    auto end() const;
    size_t size() const noexcept;
    path get_exe_path() const;
    bool find_and_pop(const std::string& arg);

    // Searches for key substr in args and removes the arg if found
    // Return example: arg = "--target=win64", key = "--target=" -> returns "win64"
    std::optional<std::string> search_and_pop(const std::string& key);

private:
    std::vector<std::string> _Args;
};

// [2] Filesystem

// Recursively creates a directory
// Returns false if failed, true if created or already existed
bool make_dir(const path& dir);


std::string path_to_filename(const path& p);                             // Replaces separator symbols with '_'
template<typename StringRange>
bool has_any_extension(const path& file, const StringRange& extensions); // Checks if file extension is same as any of provided

template<typename StringRange>
std::vector<path> find_files(const path& dir, const StringRange& extensions, bool at_least_one = false);
std::vector<path> find_sources(const path& dir, bool at_least_one = false);
std::vector<path> find_headers(const path& dir, bool at_least_one = false);

path get_cache_dir();                                       // Returns a path to code builder cache folder
std::optional<std::string> get_file_hash(const path& file); // Calculates SHA256 hash from the file data
bool save_file_hash(const path& file);                      // Calculates and saves file hash to cache directory

// Returns the hash of a file stored in the cache directory
// Saves current file cache if not found
std::optional<std::string> get_file_hash_cache(const path& file);

// Tries to rebuild itself if old cb.cpp != new cb.cpp
// Returns true if rebuilded and executed the new version, false otherwise
bool try_rebuild_itself(parser args, const path& file = "./cb.cpp");

// [3] Getter for environmental variables

std::string get_env_var(const std::string& variable_name);

// [4] Command builder

class command {
    void _append_sources(const path& file_or_dir);
    void _append_include(const path& dir);

public:
    template<typename ...String, string_rep<String...> = 0>
    void append(String ...string);                             // Appends raw strings
    template<typename ...Path, path_rep<Path...> = 0>
    void append_source(Path ...file_or_dir);                   // Appends passed source files and all source files found in passed directories
    template<typename ...Path, path_rep<Path...> = 0>
    void append_include(Path ...dir);                          // Appends "-Ipath1", "-Ipath2", ...
    void append_output(const fs::path& out);                   // Appends "-o out"
    void append_lib(const std::string& name);                  // Appends "-lname"
    void append_lib(const path& dir, const std::string& name); // Appends "-Lpath", "-lname"
    std::string to_string() const;                             // Returns command as a single string

    // Executes in the current thread
    // if _DEBUG - only prints to console
    void run() const;
    void clear() noexcept; // Clears the command buffer

private:
    std::vector<std::string> _Buffer;
};

// Implementation -----------------------------------------------------------------------

// [1] Args parser

template<typename StringRange>
std::optional<std::string> search_and_erase(StringRange& strings, const std::string& key) {
    std::string::iterator key_first;
    auto arg = std::find_if(strings.begin(), strings.end(),
        [&](std::string& str) {
        key_first = std::search(str.begin(), str.end(), key.begin(), key.end());
        return key_first != str.end();
    });

    if (arg != strings.end()) {
        std::advance(key_first, key.size());
        arg->erase(arg->begin(), key_first);
        std::string ret = *arg;
        strings.erase(arg);
        return ret;
    }
    else
        return std::nullopt;
}

parser::parser(int argc, char** argv) {
    // Path to the executable always the first arg, so argc >= 1
    while (argc--)
        _Args.emplace_back(*argv++);
}

auto parser::begin() const {
    return _Args.cbegin();
}

auto parser::end() const {
    return _Args.cend();
}

size_t parser::size() const noexcept {
    return _Args.size();
}

path parser::get_exe_path() const {
    return path{ *_Args.begin() };
}

bool parser::find_and_pop(const std::string& arg) {
    auto it = std::find(_Args.begin(), _Args.end(), arg);
    if (it != _Args.end()) {
        _Args.erase(it);
        return true;
    }
    return false;
}

std::optional<std::string> parser::search_and_pop(const std::string& key) {
    return search_and_erase(_Args, key);
}

// [2] Filesystem

bool make_dir(const path& dir) {
    if (fs::exists(dir))
        return true;

    std::error_code ec;
    fs::create_directories(dir, ec); // BUG: always returns false
    if (ec) {
        printf("[ERROR] Failed to create %s %s\n", dir.string().c_str(), ec.message().c_str());
        return false;
    }
    return true;
}

std::string path_to_filename(const path& p) {
    // The user can specify separator other than fs::preferred_separator
    // by constructing a path from a string, so checking for both '/' and '\\'
    std::string ret{ p.string() };
    for (auto& c : ret)
        if (c == '/' || c == '\\')
            c = '_';
    return ret;
}

template<typename StringRange>
bool has_any_extension(const path& file, const StringRange& extensions) {
    static_assert(std::is_same_v<typename StringRange::value_type, std::string>,
        "Must contain string");

    if (!fs::exists(file)) {
        printf("[ERROR] The file %s does not exist\n", file.string().c_str());
        return false;
    }
    for (auto& ext : extensions)
        if (file.extension() == ext)
            return true;
    return false;
}

template<typename StringRange>
std::vector<path> find_files(const path& dir, const StringRange& extensions, bool at_least_one) {
    if (!fs::is_directory(dir)) {
        printf("[ERROR] Is not a directory: %s\n", dir.string().c_str());
        return {};
    }
    std::vector<path> ret;
    for (auto& entry : fs::directory_iterator{ dir })
        if (has_any_extension(entry, extensions)) {
            ret.emplace_back(entry);
            if (at_least_one)
                return ret;
        }
    return ret;
}

std::vector<path> find_sources(const path& dir, bool at_least_one) {
    return find_files(dir, SourceExtensions, at_least_one);
}

std::vector<path> find_headers(const path& dir, bool at_least_one) {
    return find_files(dir, HeaderExtensions, at_least_one);
}

path get_cache_dir() {
    static path ret{ "./cb_cache/" };
    return ret;
}

bool save_file_hash(const path& file) {
    if (auto hash = get_file_hash(file)) {
        const path cache_path{ get_cache_dir() / path_to_filename(file) };
        std::ofstream os{ cache_path, std::ios::binary };
        if (!os) {
            printf("[ERROR] Can't open or create: %s\n", cache_path.string().c_str());
            return false;
        }
        os.write(hash->data(), hash->size());
        os.close();
        return true;
    }
    return false;
}

std::optional<std::string> get_file_hash_cache(const path& file) {
    const path cache_path{ get_cache_dir() / path_to_filename(file) };
    if (fs::exists(cache_path)) {
        std::ifstream is{ cache_path, std::ios::binary };
        if (!is) {
            printf("[ERROR] Can't open: %s\n", cache_path.string().c_str());
            return std::nullopt;
        }
        const auto size = fs::file_size(cache_path);
        std::string ret(size, 0);
        is.read((char*)ret.data(), ret.size());
        return ret;
    }
    return std::nullopt;
}

std::optional<std::string> get_file_hash(const path& file) {
    if (!fs::exists(file)) {
        printf("[ERROR] Doesn't exist: %s\n", file.string().c_str());
        return std::nullopt;
    }
    if (fs::is_directory(file)) {
        printf("[ERROR] Is not a file: %s\n", file.string().c_str());
        return std::nullopt;
    }

    std::ifstream is{ file, std::ios::binary };
    if (!is) {
        printf("[ERROR] Failed to open: %s\n", file.string().c_str());
        is.close();
        return std::nullopt;
    }
    const auto size = fs::file_size(file); // validate: < u32max?
    std::vector<uint8_t> buffer(size);
    is.read((char*)buffer.data(), buffer.size());
    is.close();

    static sha256_context ctx;
    sha256_init(&ctx);
    sha256_hash(&ctx, buffer.data(), (uint32_t)buffer.size());
    std::string ret(32, 0);
    sha256_done(&ctx, (uint8_t*)ret.data());
    return ret;
}

bool try_rebuild_itself(parser args, const path& file) {
    if (!make_dir(get_cache_dir()))
        return false;
    
    auto my_hash  = get_file_hash(file);
    auto old_hash = get_file_hash_cache(file);
    if (!old_hash) {
        save_file_hash(file);
        return false;
    }
    else if (my_hash && *my_hash == *old_hash)
        return false;
    
    const fs::path exe_new{ args.get_exe_path() };
    const fs::path exe_old{ exe_new.string() + ".old" };

    // Clear exe_old if exists from previous recompilations
    std::error_code ec;
    if (fs::exists(exe_old))
        if (!fs::remove(exe_old, ec)) // Remove cb.exe.old
             printf("[ERROR] Removing failed: %s\n", ec.message().c_str());

    // Rename cb.exe -> cb.exe.old
    printf("Recompiling: %s -> %s\n", exe_new.string().c_str(), exe_old.string().c_str());
    fs::rename(exe_new, exe_old, ec);
    if (ec) {
        printf("[ERROR] Renaming failed: %s\n", ec.message().c_str());
        return false;
    }

    // Try to compile cb.cpp
    command cmd;
    cmd.append("clang", "-std=c++17"); // todo compiler setter/gstate?
    cmd.append_source(file);
    cmd.append_output(exe_new);
    cmd.run();

    // Run new cb.exe if compilation successful
    if (fs::exists(exe_new)) {
        // Successfully compiled -> save hash to cache dir
        save_file_hash(file);

        // Run script
        cmd.clear();
#ifdef _WIN32
        cmd.append(exe_new.string());
#else // UNIX
        cmd.append("./" + exe_new);
#endif // _WIN32
        cmd.run();
        return true;
    }
    else {
        // Rename cb.exe.old -> cb.exe and continue this script
        printf("Compilation failed: %s -> %s\n", exe_old.string().c_str(), exe_new.string().c_str());
        fs::rename(exe_old, exe_new, ec);
        if (ec)
            printf("[ERROR] Renaming failed: %s\n", ec.message().c_str());
        return false;
    }
}

// [3] Getter for environmental variables

std::string get_env_var(const std::string& variable_name) {
    static constexpr size_t init_size{ 256 };
    std::string ret(init_size, 0);
    size_t required_size;

    getenv_s(&required_size, (char*)ret.data(), ret.size(), variable_name.c_str());
    ret.resize(required_size);
    if (required_size > init_size)
        getenv_s(&required_size, (char*)ret.data(), ret.size(), variable_name.c_str());
    ret.erase(--ret.end()); // std::string is already null-terminated (since C++11)
    return ret;
}

// [4] Command builder

void command::_append_sources(const path& file_or_dir) {
    if (fs::is_directory(file_or_dir)) {
        const auto files = find_sources(file_or_dir);
        if (files.empty())
            printf("[ERROR] No source files in the: %s\n", file_or_dir.string().c_str());
        else for (auto& f : files)
            _Buffer.emplace_back(f.string());
    }
    else if (has_any_extension(file_or_dir, SourceExtensions))
        _Buffer.emplace_back(file_or_dir.string());
    else
        printf("[ERROR] Is not a source file: %s\n", file_or_dir.string().c_str());
}

void command::_append_include(const path& dir) {
    if (!fs::is_directory(dir))
        printf("[ERROR] Is not a directory: %s\n", dir.string().c_str());
    else
        _Buffer.emplace_back("-I" + dir.string());
}

// Appends raw strings
template<typename ...String, string_rep<String...>>
void command::append(String ...string) {
    (..., _Buffer.emplace_back(string));
}

// Appends passed source files and all source files found in passed directories
template<typename ...Path, path_rep<Path...>>
void command::append_source(Path ...file_or_dir) {
    (..., _append_sources(file_or_dir));
}

// Appends "-Ipath1", "-Ipath2", ...
template<typename ...Path, path_rep<Path...>>
void command::append_include(Path ...dir) {
    (..., _append_include(dir));
}

// Appends "-o out"
void command::append_output(const fs::path& out) {
    if (auto existing = search_and_erase(_Buffer, "-o"))
        printf("[WARNING] Replaced %s with %s\n", existing->c_str(), out.string().c_str());
    _Buffer.emplace_back("-o " + out.string());
}

// Appends "-lname"
void command::append_lib(const std::string& name) {
    _Buffer.emplace_back("-l" + name);
}

// Appends "-Lpath", "-lname"
void command::append_lib(const path& dir, const std::string& name) {
    // todo: validate lib path?
    _Buffer.emplace_back("-L" + dir.string());
    append_lib(name);
}

// Returns command as a single string
std::string command::to_string() const {
    std::string ret;
    for (size_t i = 0; i < _Buffer.size(); i++) {
        ret += _Buffer[i];
        if (i < _Buffer.size() - 1)
            ret += ' ';
    }
    return ret;
}

// Executes in the current thread
// if _DEBUG - only prints to console
void command::run() const {
    const auto str = to_string();
    if (!str.empty()) {
#ifndef _DEBUG
        printf("Executing: %s\n", str.c_str());
        system(str.c_str());
#else
        printf("[DEBUG] Executing: %s\n", str.c_str());
#endif // !_DEBUG
    }
}

void command::clear() noexcept {
    _Buffer.clear();
}
} // namespace cb

#undef _CRT_SECURE_NO_WARNINGS

#endif // !CODE_BUILDER_INCLUDE_HPP