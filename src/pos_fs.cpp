#include "../include/pos_fs.hpp"

bool directory_exists(const fs::path& p) {
    return fs::exists(p) && fs::is_directory(p);
}

std::filesystem::__cxx11::directory_iterator get_dirs(std::string path) {
    return fs::directory_iterator(path);
}

std::ofstream mk_file(const std::string& path) {
    return std::ofstream(path);
}

void rm_file(std::string path) {
    fs::remove(path);
}

void mk_dir(std::string path) {
    fs::create_directories(path);
}