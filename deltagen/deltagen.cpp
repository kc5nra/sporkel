#include <algorithm>
#include <map>
#include <fstream>
#include <sodium.h>

#include "deltagen.h"
#include "base64.h"

bool delta_info_equals(struct delta_info &l, struct delta_info& r) {
    if (l.hash.compare(r.hash) != 0) {
        return false;
    }
    if (l.type != r.type) {
        return false;
    }
    return l.size != r.size;
}

struct delta_info make_delta_info(sys::recursive_directory_iterator &i)
{
    struct delta_info di;
    
    di.type = i->status().type();
    di.size = sys::file_size(i->path());
    di.hash = hash_file(i->path(), di.size);
    
    return di;   
}

std::string hash_file(const sys::path &path, const size_t size)
{
    crypto_generichash_state state;
    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash_init(&state, NULL, 0, sizeof(hash));

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
    crypto_generichash_final(&state, hash, sizeof(hash));
    
    return std::string(base64_encode(&hash[0], sizeof(hash)));
}

sys::path make_relative(const sys::path &parent_path, const sys::path &child_path)
{
    std::string parent(parent_path.string());
    std::string child(child_path.string());
    size_t parent_len = parent.length();

    if (child.length() >= parent_len && child.substr(0, parent_len) == parent)
        return sys::path(child.substr(parent_len));

    return child_path;
}

bool has_option(char **begin, char **end, const std::string &option)
{
	return std::find(begin, end, option) != end;
}

#define HAS_OPTION(x) has_option(argv, argv + argc, x)
#define OPTION(x) (x < argc ? argv[x] : NULL)

int create(char *before_tree, char *after_tree, char *patch_file);
int apply(char *tree, char *patch_file);

int show_help(int result, std::string &bn) {
	if (result == 1) {
		printf("usage: %s <command> <args>\n\n", bn.c_str());
		printf("    create <before_tree> <after_tree> <patch_file>\n", bn.c_str());
		printf("    apply <tree> <patch_file>\n", bn.c_str());
	}
	return result;
}

int main(int argc, char **argv)
{
	
	std::string bn = sys::basename(sys::path(argv[0]));

	if (HAS_OPTION("-h") || HAS_OPTION("--help")) {
		return show_help(1, bn);
	}

	int result = 0;

	bool is_create = HAS_OPTION("create");
	bool is_apply = HAS_OPTION("apply");
	if (is_create ^ is_apply) {
		if (is_create)
			result = create(OPTION(2), OPTION(3), OPTION(4));
		else
			result = apply(OPTION(2), OPTION(3));
	}
	else {
		fprintf(stderr, "error: create or apply command must be specified\n");
		result = 1;
	}

	return show_help(result, bn);
}

int create(char *before_tree, char *after_tree, char *patch_file)
{
	if (!before_tree) {
		fprintf(stderr, "error: <before_tree> missing\n");
		return 1;
	}

	if (!after_tree) {
		fprintf(stderr, "error: <after_tree> missing\n");
		return 1;
	}

	if (!patch_file) {
		fprintf(stderr, "error: <patch_file> missing\n");
		return 1;
	}

	sys::path before_path(before_tree);
	sys::path after_path(after_tree);
	sys::path patch_path(patch_file);
	
	if (!sys::is_directory(before_path)) {
		fprintf(stderr, "error: <before_tree> '%s' is not a directory\n", before_path.string().c_str());
		return 1;
	}

	if (!sys::is_directory(after_path)) {
		fprintf(stderr, "error: <after_tree> option '%s' is not a directory\n", after_path.string().c_str());
		return 1;
	}

	if (sys::exists(patch_path)) {
		fprintf(stderr, "error: <patch_file> '%s' already exists\n", patch_path.string().c_str());
		return 2;
	}

    std::map<std::string, struct delta_info> before_tree_state;
    sys::recursive_directory_iterator end;
    for (sys::recursive_directory_iterator i(before_path); i != end; ++i) {
        sys::file_type type = i->status().type();
        if (!sys::is_directory(i->status()) && !sys::is_regular_file(i->status()) && !sys::is_symlink(i->status())) {
            continue;
        }

        sys::path rel_path(make_relative(before_path, i->path()));
        before_tree_state[rel_path.string()] = make_delta_info(i);
    }

	return 0;
}

int apply(char *tree, char *patch_file)
{
	return 0;
}
