// C++ Project building system
// Requires C++14

// Pavlygin Danil 2026

// Done:
// Append
// Directory and source-file validation
// Environmantal variable getter

// Todo:
// Args parsing
// Escape symbols
// Tell if there is no headers/sources in passed directory
// Validate lib path?
// Compiler detection
// Library linking
// Concurrent compilation
// package-config

#ifndef CODE_BUILDER_INCLUDE_HPP
#define CODE_BUILDER_INCLUDE_HPP

// Uncomment to enable logging
//#define CODE_BUILDER_LOG_ENABLE

#include <array>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <type_traits>
#include <vector>

#ifdef CODE_BUILDER_LOG_ENABLE
#define log_error(cstr) printf("ERROR: %s\n", cstr)
#else
#define log_error(cstr)
#endif // CODE_BUILDER_LOG_ENABLE

// Type validation helper (C++11 insanity)

#define CONCEPT(name, impl_name, condition, message)        \
    template<typename...>                                   \
    struct impl_name;                                       \
                                                            \
    template<>                                              \
    struct impl_name<> {                                    \
        using type = int;                                   \
    };                                                      \
                                                            \
    template<typename This, typename ...Rest>               \
    struct impl_name<This, Rest...> : impl_name<Rest...> {  \
        using Base = impl_name<Rest...>;                    \
        static constexpr bool test = condition<This>::value;\
        static_assert(test, message);                       \
        using type = typename Base::type;                   \
    };                                                      \
                                                            \
    template<typename ...Ts>                                \
    using name = typename impl_name<Ts...>::type;

template<typename T>
struct _string_rep_cond : std::is_constructible<std::string, T> {};

CONCEPT(string_rep, _string_rep, _string_rep_cond, "The types must be string or const char*")

// Auto-detectedable extensions
static const std::array<std::string, 3> SourceExtensions{
    ".c",
    ".cpp",
    ".cxx"
};

static const std::array<std::string, 3> HeaderExtensions{
    ".h",
    ".hpp"
};

namespace cb
{
// Environmental variable value getter

inline std::string get_env_variable(const std::string& variable_name) {
    static constexpr size_t init_size{ 256 };
    std::string ret(init_size, 0);
    size_t required_size;

    getenv_s(&required_size, (char*)ret.data(), ret.size(), variable_name.c_str());
    ret.resize(required_size);
    if (required_size > init_size)
        getenv_s(&required_size, (char*)ret.data(), ret.size(), variable_name.c_str());
    return ret;
}

// Args parser

class Args {
public:
    Args(int argc, char** argv) {
        // Path to the executable always the first arg, so argc >= 1
        while (argc--)
            _Args.emplace_back(*argv++);
    }

    auto begin() const {
        return _Args.cbegin();
    }

    auto end() const {
        return _Args.cend();
    }

    bool find(const std::string& arg) const {
        return std::find(_Args.begin(), _Args.end(), arg) != _Args.end();
    }

    bool find_and_erase(const std::string& arg) {
        auto it = std::find(_Args.begin(), _Args.end(), arg);
        if (it != _Args.end()) {
            _Args.erase(it);
            return true;
        }
        return false;
    }

private:
    std::vector<std::string> _Args;
};

// Command builder

class Command {
    // Dummy for recursive appending
    void append() {}

    // Avoids zero-terminated strings
    void emplace_string(std::string& str) {
        auto last_char = --str.end();
        if (*last_char == '\0')
            str.erase(last_char);
        _Buffer.emplace_back(str);
        log_error(name.c_str());
    }

public:
    // Appends raw strings
    template<typename String1, typename ...String, string_rep<String1, String...> = 0>
    void append(String1 str1, String ...str) {
        emplace_string(str1);
        append(str...);
    }

    // Appends "-lname"
    void append_lib(std::string name) {
        name.insert(0, "-l");
        emplace_string(name);
    }

    // Appends "-Lpath" "-lname"
    void append_lib(std::string path, std::string name) {
        path.insert(0, "-L");
        emplace_string(path);
        append_lib(name);
    }

    // Returns command as a single string
    std::string to_string() const {
        std::string ret;
        for (auto& s : _Buffer) {
            ret.append(s);
            ret.append(" ");
        }
        return ret;
    }

    // Executes command in terminal
    void run() const {
        const auto str = to_string();
        if (!str.empty()) {
            printf("Executing: %s\n", str.c_str());
#ifndef _DEBUG
            system(str.c_str());
#endif // _DEBUG
        }
    }

private:
    std::vector<std::string> _Buffer;
};
} // namespace cb

#endif // !CODE_BUILDER_INCLUDE_HPP
