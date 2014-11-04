#pragma once

#include <filesystem>
#include <string>

using namespace std::tr2;

struct delta_info {
    std::string hash;
    sys::file_type type;
    unsigned long long size;
};

std::string hash_file(const sys::path &path, size_t size);