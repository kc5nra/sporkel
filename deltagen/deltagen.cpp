#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <fstream>

#include <cereal/archives/binary.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/string.hpp>

#include "base64.h"
#include "deltagen.h"
#include "deltacommon.h"
#include "bscommon.h"

struct delta_info make_delta_info(recursive_directory_iterator &i)
{
	struct delta_info di;
	
	di.type = i->status().type();
	di.size = 0;
	if (is_regular_file(i->status()))
		di.size = file_size(i->path());
	di.hash = hash_entry(i);
	di.deleted = false;

	return di;
}

bool delta_info_equals(struct delta_info &l, struct delta_info& r) {
	if (l.hash.compare(r.hash) != 0) {
		return false;
	}
	if (l.type != r.type) {
		return false;
	}
	return l.size == r.size;
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
		printf("    create <before_tree> <after_tree> <patch_file>\n");
		printf("    apply <tree> <patch_file>\n");
	}
	return result;
}

int main(int argc, char **argv)
{
	
	std::string bn = basename(path(argv[0]));

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

	path before_path(before_tree);
	path after_path(after_tree);
	path patch_path(patch_file);
	
	if (!is_directory(before_path)) {
		fprintf(stderr, "error: <before_tree> '%s' is not a directory\n", before_path.generic_string().c_str());
		return 1;
	}

	if (!is_directory(after_path)) {
		fprintf(stderr, "error: <after_tree> option '%s' is not a directory\n", after_path.generic_string().c_str());
		return 1;
	}

	if (exists(patch_path)) {
		fprintf(stderr, "error: <patch_file> '%s' already exists\n", patch_path.generic_string().c_str());
		return 2;
	}

	std::map<std::string, struct delta_info> before_tree_state;
	std::map<std::string, struct delta_info> after_tree_state;
	
	struct delta_info deleted;
	deleted.deleted = true;

	unsigned char hash[crypto_generichash_BYTES];
	
	crypto_generichash_state state;
	crypto_generichash_init(&state, NULL, 0, sizeof(hash));

	printf("processing %s...\n", before_path.generic_string().c_str());
	process_tree(before_path, [&](path &path, recursive_directory_iterator &i) {
		auto before_info = make_delta_info(i);
		auto key(path.generic_string());
		hash_delta_info(key, before_info, state);
		before_tree_state[key] = before_info;
		after_tree_state[key] = deleted;
	});

	crypto_generichash_final(&state, hash, sizeof(hash));
	std::string before_tree_hash(base64_encode((const unsigned char *) &hash[0], sizeof(hash)));

	crypto_generichash_init(&state, NULL, 0, sizeof(hash));

	printf("processing %s...\n", after_path.generic_string().c_str());
	process_tree(after_path, [&](path &path, recursive_directory_iterator &i) {
		auto after_info = make_delta_info(i);
		auto key(path.generic_string());
		hash_delta_info(key, after_info, state);
		if (before_tree_state.count(key)) {
			auto &before_info = before_tree_state[key];
			if (delta_info_equals(before_info, after_info)) {
				after_tree_state.erase(key);
				return;
			}
		}
		
		after_tree_state[key] = after_info;
	});

	crypto_generichash_final(&state, hash, sizeof(hash));
	std::string after_tree_hash(base64_encode((const unsigned char *) &hash[0], sizeof(hash)));

	printf("before tree: '%s'\n", before_path.generic_string().c_str());
	printf("    hash: '%s'\n", before_tree_hash.c_str());
	std::cout << "    file count: " << before_tree_state.size() << std::endl;
	printf("after tree: '%s'\n", after_path.generic_string().c_str());
	printf("    hash: '%s'\n", after_tree_hash.c_str());
	std::cout << "    mod cnt: " << after_tree_state.size() << std::endl;

	printf("generating delta operations...\n");
	
	struct delta_op_toc toc;

	for (auto i = after_tree_state.begin(); i != after_tree_state.end(); ++i) {
		auto &after_info = i->second;

		if (after_info.deleted) {
			printf("d %s\n", i->first.c_str());
			continue;
		}

		if (before_tree_state.count(i->first)) {
			auto &before_info = before_tree_state[i->first];
			if (before_info.type != after_info.type) {
				printf("{\n  d %s (%d)\n", i->first.c_str(), before_info.type);
				printf("  a %s (%d)\n}\n", i->first.c_str(), after_info.type);
				toc.ops.push_back(delta_op(delta_op_type::DELETE, i->first));
				toc.ops.push_back(delta_op(delta_op_type::ADD, i->first));
			}
			else {
				printf("b %s\n", i->first.c_str());
				toc.ops.push_back(delta_op(delta_op_type::PATCH, i->first));
			}
		}
		else {
			printf("a %s\n", i->first.c_str());
			toc.ops.push_back(delta_op(delta_op_type::ADD, i->first));
		}
	}

	std::ofstream ofs(patch_path.native().c_str(), std::ios::binary);
	cereal::PortableBinaryOutputArchive archive(ofs);
	archive(toc);
	ofs.close();

	struct delta_op_toc toc_in;

	std::ifstream ifs(patch_path.native().c_str(), std::ios::binary);
	cereal::PortableBinaryInputArchive iarchive(ifs);
	iarchive(toc);
	ifs.close();

	return 0;
}

int apply(char *tree, char *patch_file)
{
	return 0;
}
