#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <sodium.h>

using namespace std::tr2;

struct delta_info {
    std::string hash;
    sys::file_type type;
    unsigned long long size;
    bool deleted;
};

sys::path make_path_relative(const sys::path &parent_path, const sys::path &child_path);
void process_tree(sys::path &path, std::function<void(sys::path &path, sys::recursive_directory_iterator &i)> f);
bool delta_info_equals(struct delta_info &l, struct delta_info& r);

void hash_delta_info(std::string &path, struct delta_info &di, crypto_generichash_state &state);
std::string hash_entry(sys::recursive_directory_iterator &i);
void hash_entry(sys::recursive_directory_iterator &i, crypto_generichash_state &state);
