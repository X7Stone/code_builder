#include "cb17.hpp"

#ifdef _WIN32
static const cb::path libs = cb::get_env_var("libs");
#else
static const fs::path libs = "~/libs/";
#endif // _WIN32

int main(int argc, char** argv) {
    cb::path utilib = libs / "utilib" / "utilib" / "tests";
    cb::path boost  = libs / "boost";
    
    cb::command cmd;
    cmd.append("clang", "-std=c++20", "-o utilib_tests.exe");
    cmd.append_include(boost.string());
    cmd.append_source(utilib.string());

    cmd.run();
}