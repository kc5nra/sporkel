#pragma once

#include <functional>
#include <boost/filesystem.hpp>
#include <string>
#include <sodium.h>

using namespace boost::filesystem;

struct delta_info {
    std::string hash;
    file_type type;
    unsigned long long size;
    bool deleted;
};

path make_path_relative(const path &parent_path, const path &child_path);
void process_tree(path &p, std::function<void(path &p, recursive_directory_iterator &i)> f);
bool delta_info_equals(struct delta_info &l, struct delta_info& r);

void hash_delta_info(std::string &path, struct delta_info &di, crypto_generichash_state &state);
std::string hash_entry(recursive_directory_iterator &i);
void hash_entry(recursive_directory_iterator &i, crypto_generichash_state &state);
