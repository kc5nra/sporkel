#include <sodium.h>

#include "base64.h"
#include "deltacommon.h"

sys::path make_path_relative(const sys::path &parent_path, const sys::path &child_path)
{
    std::string parent(parent_path.string());
    std::string child(child_path.string());
    size_t parent_len = parent.length();

    if (child.length() >= parent_len && child.substr(0, parent_len) == parent)
        return sys::path(child.substr(parent_len));

    return child_path;
}

void process_tree(sys::path &path, std::function<void(sys::path &path, sys::recursive_directory_iterator &i)> f)
{
    sys::recursive_directory_iterator end;
    for (sys::recursive_directory_iterator i(path); i != end; ++i) {
        sys::file_type type = i->status().type();
        if (!sys::is_directory(i->status()) && !sys::is_regular_file(i->status()) && !sys::is_symlink(i->status())) {
            continue;
        }

        sys::path rel_path(make_path_relative(path, i->path()));
        if (!rel_path.empty())
            f(rel_path, i);
    }
}

void hash_delta_info(std::string &path, struct delta_info &di, crypto_generichash_state &state)
{
    crypto_generichash_update(&state, (const unsigned char *) path.c_str(), sizeof(di.hash.c_str()));
    crypto_generichash_update(&state, (const unsigned char *) &di.type, sizeof(decltype(di.type)));
    crypto_generichash_update(&state, (const unsigned char *) &di.size, sizeof(decltype(di.size)));
    crypto_generichash_update(&state, (const unsigned char *) di.hash.c_str(), sizeof(di.hash.c_str()));
}

void hash_entry(sys::recursive_directory_iterator &i, crypto_generichash_state &state)
{
    
    auto &path = i->path();
    size_t size = (size_t)sys::file_size(i->path());

    if (sys::is_regular(i->status()) || sys::is_symlink(i->status())) {

        char chunk_buffer[16 * 1024];
        size_t chunk_buffer_size = sizeof(chunk_buffer);
        size_t chunk_cnt = size / chunk_buffer_size;
        size_t last_chunk_size = size % chunk_buffer_size;

        std::ifstream file(path.string(), std::ifstream::binary);

        if (last_chunk_size != 0)
            ++chunk_cnt;
        else
            last_chunk_size = chunk_buffer_size;

        for (size_t chunk = 0; chunk < chunk_cnt; ++chunk) {
            size_t chunk_size = chunk_buffer_size;
            if (chunk == chunk_cnt - 1)
                chunk_size = last_chunk_size;

            file.read(&chunk_buffer[0], chunk_size);
            crypto_generichash_update(&state, (unsigned char *)&chunk_buffer[0], chunk_size);
        }

        return;
    }

    if (sys::is_directory(i->status())) {
        crypto_generichash_update(&state, (const unsigned char *)"d", 1);
    }
}

std::string hash_entry(sys::recursive_directory_iterator &i)
{
    crypto_generichash_state state;
    unsigned char hash[crypto_generichash_BYTES];
    
    crypto_generichash_init(&state, NULL, 0, sizeof(hash));
    hash_entry(i, state);
    crypto_generichash_final(&state, hash, sizeof(hash));

    return std::string(base64_encode(&hash[0], sizeof(hash)));
}