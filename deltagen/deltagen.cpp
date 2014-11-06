#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <fstream>

#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/bzip2.hpp>

#include <cereal/archives/binary.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/string.hpp>

#include "base64.h"
#include "deltagen.h"
#include "deltacommon.h"
#include "scopeguard.h"
#include <bscommon.h>

using namespace boost::iostreams;

delta_info make_delta_info(recursive_directory_iterator &i)
{
	delta_info di;
	
	di.type = i->status().type();
	di.size = 0;
	if (is_regular_file(i->status()))
		di.size = file_size(i->path());
	di.hash = hash_entry(i);
	di.deleted = false;

	return di;
}

bool operator==(const delta_info &l, const delta_info &r) {
	return l.type == r.type && l.size == r.size && l.hash == r.hash;
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

std::string get_tree_hash(const std::map<std::string, delta_info> &tree) {
	unsigned char hash[crypto_generichash_BYTES];
	crypto_generichash_state state;
	crypto_generichash_init(&state, NULL, 0, sizeof(hash));
	for (auto &i : tree) {
		hash_delta_info(i.first, i.second, state);
	}
	crypto_generichash_final(&state, hash, sizeof(hash));
	return base64_encode((const unsigned char *) &hash[0], sizeof(hash));
}

void get_file_contents(path &p, size_t size, std::vector<uint8_t> &buf) {
	std::ifstream f(p.native(), std::ios::binary);
	buf.resize(size);
	f.read(reinterpret_cast<char*>(buf.data()), size);
}

void set_file_contents(path &p, std::vector<uint8_t> &buf) {
	std::ofstream f(p.native(), std::ios::binary);
	f.write((char *)buf.data(), buf.size());
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

	std::map<std::string, delta_info> before_tree_state;
	std::map<std::string, delta_info> after_tree_state_unmod;
	std::map<std::string, delta_info> after_tree_state;

	delta_info deleted;
	deleted.deleted = true;

	printf("processing %s...\n", before_path.generic_string().c_str());
	process_tree(before_path, [&](path &path, recursive_directory_iterator &i) {
		auto before_info = make_delta_info(i);
		auto key(path.generic_string());
		before_tree_state[key] = before_info;
		after_tree_state[key] = deleted;
	});

	printf("processing %s...\n", after_path.generic_string().c_str());
	process_tree(after_path, [&](path &path, recursive_directory_iterator &i) {
		auto after_info = make_delta_info(i);
		auto key(path.generic_string());
		after_tree_state_unmod[key] = after_info;

		auto res = before_tree_state.find(key);
		if (res != end(before_tree_state)) {
			if (res->second == after_info) {
				after_tree_state.erase(key);
				return;
			}
		}
		
		after_tree_state[key] = after_info;
	});

	delta_op_toc toc;
	toc.ops.reserve(after_tree_state.size() * 2);
	toc.before_hash = get_tree_hash(before_tree_state);
	toc.after_hash = get_tree_hash(after_tree_state_unmod);
	
	printf("before tree: '%s'\n", before_path.generic_string().c_str());
	printf("    hash: '%s'\n", toc.before_hash.c_str());
	std::cout << "    file count: " << before_tree_state.size() << std::endl;
	printf("after tree: '%s'\n", after_path.generic_string().c_str());
	printf("    hash: '%s'\n", toc.after_hash.c_str());
	std::cout << "    mod cnt: " << after_tree_state.size() << std::endl;

	printf("generating delta operations...\n");
	
	int a_op_cnt = 0;
	int b_op_cnt = 0;
	int d_op_cnt = 0;
	
	for (auto &i : after_tree_state) {
		auto &after_info = i.second;

		if (after_info.deleted) {
			d_op_cnt++;
			toc.ops.emplace_back(delta_op_type::DELETE, i.first, file_type::status_unknown);
			continue;
		}

		auto res = before_tree_state.find(i.first);
		if (res == end(before_tree_state)) {
			a_op_cnt++;
			toc.ops.emplace_back(delta_op_type::ADD, i.first, after_info.type);
			continue;
		}

		auto &before_info = res->second;
		if (before_info.type != after_info.type) {
			d_op_cnt++; a_op_cnt++;
			toc.ops.emplace_back(delta_op_type::DELETE, i.first, before_info.type);
			toc.ops.emplace_back(delta_op_type::ADD, i.first, after_info.type);
		}
		else {
			b_op_cnt++;
			toc.ops.emplace_back(delta_op_type::PATCH, i.first, before_info.type);
		}
	}

	printf("  %4d deletions\n  %4d additions\n  %4d bpatches\n", d_op_cnt, a_op_cnt, b_op_cnt);

	std::ofstream ofs(patch_path.native(), std::ios::binary);
	filtering_ostream filter;
	filter.push(bzip2_compressor());
	filter.push(ofs);

	cereal::PortableBinaryOutputArchive archive(filter);

	archive(toc);

	std::vector<uint8_t> delta;

	for (auto &i : toc.ops) {
		if (i.ftype != file_type::regular_file)
			continue;
		switch (i.type) {
		case delta_op_type::ADD:
		{
			path p(after_path / path(i.path));
			size_t s = file_size(p);
			get_file_contents(p, s, delta);
			archive(delta);
			break;
		}
		case delta_op_type::PATCH:
		{
			path p1(before_path / path(i.path));
			path p2(after_path / path(i.path));
			size_t s1 = file_size(p1);
			size_t s2 = file_size(p2);
			std::vector<uint8_t> p1_data;
			std::vector<uint8_t> p2_data;
			get_file_contents(p1, s1, p1_data);
			get_file_contents(p2, s2, p2_data);
			auto max_size = bsdiff_patchsize_max(s1, s2);
			delta.resize(max_size + 1);
			std::cout << "diffing " << i.path << " (" << s1 << "b -> " << s2 << "b)...";
			int actual_size = bsdiff(p1_data.data(), s1, p2_data.data(), s2, delta.data(), max_size);
			delta.resize(actual_size);
			archive(delta);
			std::cout << " done. (" << actual_size << "b patch)" << std::endl;
			break;
		}
		case delta_op_type::DELETE:
			break;
		}
	}

	return 0;
}

int apply(char *before_tree, char *patch_file)
{
	if (!before_tree) {
		fprintf(stderr, "error: <before_tree> missing\n");
		return 1;
	}

	if (!patch_file) {
		fprintf(stderr, "error: <patch_file> missing\n");
		return 1;
	}

	path before_path(before_tree);
	path patch_path(patch_file);

	if (!is_directory(before_path)) {
		fprintf(stderr, "error: <before_tree> '%s' is not a directory\n", before_path.generic_string().c_str());
		return 1;
	}

	if (!exists(patch_path) || !is_regular_file(patch_path)) {
		fprintf(stderr, "error: <patch_file> '%s' does not exist or not a file\n", patch_path.generic_string().c_str());
		return 2;
	}
	
	path after_path(get_temp_directory());
	
	printf("copying %s to %s...\n", before_path.generic_string().c_str(), after_path.generic_string().c_str());

	copy_directory_recursive(before_path, after_path);
	DEFER { remove_all(after_path); };

	std::ifstream ifs(patch_path.native(), std::ios::binary);
	filtering_istream filter;

	filter.push(bzip2_decompressor());
	filter.push(ifs);

	delta_op_toc toc;

	cereal::PortableBinaryInputArchive archive(filter);
	archive(toc);

	printf("validating tree initial state %s...\n", after_path.generic_string().c_str());

	std::map<std::string, delta_info> before_tree_state;
	process_tree(before_path, [&](path &path, recursive_directory_iterator &i) {
		before_tree_state[path.generic_string()] = make_delta_info(i);
	});

	std::string before_tree_hash = get_tree_hash(before_tree_state);
	if (before_tree_hash != toc.before_hash) {
		fprintf(stderr, "error: current tree hash %s does not match the expected tree hash %s\n", 
				before_tree_hash.c_str(), toc.before_hash.c_str());
	}

	printf("applying patches...\n");

	std::vector<uint8_t> delta;
	std::vector<uint8_t> before_file;
	std::vector<uint8_t> after_file;

	for (auto &i : toc.ops) {
		switch (i.type) {
		case delta_op_type::ADD:
		{
			auto p = after_path / i.path;
			if (i.ftype == file_type::directory_file) {
				create_directory(p);
				continue;
			}
			// symlink handling here
			archive(delta);
			set_file_contents(p, delta);
			continue;
		}
		case delta_op_type::PATCH: {
			auto p = after_path / i.path;
			auto before_size = file_size(p);

			get_file_contents(p, before_size, before_file);
			archive(delta);
			auto after_size = bspatch_newsize(delta.data(), delta.size());		
			after_file.resize(after_size);
			int res = bspatch(before_file.data(), before_file.size(), delta.data(), delta.size(), after_file.data(), after_file.size());
			if (res != 0) {
				fprintf(stderr, "failed patching %s\n", p.generic_string().c_str());
			}
			set_file_contents(p, after_file);
			continue;
		}
		case delta_op_type::DELETE:
			auto p = after_path / i.path;
			remove_all(p);
			continue;
		}
	}

	printf("validating tree patched state %s...\n", after_path.generic_string().c_str());

	std::map<std::string, delta_info> after_tree_state;
	process_tree(after_path, [&](path &path, recursive_directory_iterator &i) {
		after_tree_state[path.generic_string()] = make_delta_info(i);
	});

	std::string after_tree_hash = get_tree_hash(after_tree_state);
	if (after_tree_hash != toc.after_hash) {
		fprintf(stderr, "error: patched tree hash %s does not match the expected tree hash %s\n",
			after_tree_hash.c_str(), toc.after_hash.c_str());
	}

	return 0;
}
