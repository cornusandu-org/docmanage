#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

bool directory_exists(const fs::path& p);
std::filesystem::__cxx11::directory_iterator get_dirs(std::string path);
std::ofstream mk_file(const std::string& path);
void rm_file(std::string path);
void mk_dir(std::string path);
