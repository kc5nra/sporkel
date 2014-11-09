#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <fstream>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <numeric>

#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/bzip2.hpp>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <boost/iostreams/filter/lzma.hpp>

#include <cereal/archives/binary.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/string.hpp>

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

#define HAS_OPTION(x) (argc >= 2 ? std::string(x) == argv[1] : false)
#define OPTION(x) (x < argc ? argv[x] : NULL)

int create(char *before_tree, char *after_tree, char *patch_file,
		char *threads, char *mem_limit, char *cache_dir);
int apply(char *tree, char *patch_file);
int keypair(char *private_key_file, char *public_key_file);
int sign(char *private_key_file, char *file);

int show_help(int result, std::string &bn) {
	if (result == 1) {
		printf("usage: %s <command> <args>\n\n", bn.c_str());
		printf("    help\n");
		printf("    create <before_tree> <after_tree> <patch_file> [threads [mem_limit [cache_dir]]]\n");
		printf("    apply <tree> <patch_file>\n");
		printf("    keypair <private_key_file> <public_key_file>\n");
		printf("    sign <private_key_file> <file>\n\n");
	}
	return result;
}

int main(int argc, char **argv)
{
	
	std::string bn = basename(path(argv[0]));

	if (HAS_OPTION("help")) {
		return show_help(1, bn);
	}

	int result = 0;

	bool is_create = HAS_OPTION("create");
	bool is_apply = HAS_OPTION("apply");
	bool is_keypair = HAS_OPTION("keypair");
	bool is_sign = HAS_OPTION("sign");

	if (is_create)
		result = create(OPTION(2), OPTION(3), OPTION(4), OPTION(5), OPTION(6), OPTION(7));
	else if (is_apply)
		result = apply(OPTION(2), OPTION(3));
	else if (is_keypair)
		result = keypair(OPTION(2), OPTION(3));
	else if (is_sign)
		result = sign(OPTION(2), OPTION(3));
	else {
		fprintf(stderr, "error: command must be specified\n");
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
	return bin2hex(hash);
}

void get_file_contents(path &p, size_t size, std::vector<uint8_t> &buf) {
	std::ifstream f(p.native(), std::ios::binary);
	buf.resize(size);
	f.read(reinterpret_cast<char*>(buf.data()), size);
}

void set_file_contents(path &p, uint8_t *data, size_t len) {
	std::ofstream f(p.native(), std::ios::binary);
	f.write((char *)data, len);
}

void write_cached_diff(const path &p, const std::vector<uint8_t> &data)
{
	create_directories(p.parent_path());
	std::ofstream f(p.native(), std::ios::binary | std::ios::trunc);

	filtering_ostream filter;
	filter.push(lzma_compressor({}, 4096));
	filter.push(f);

	cereal::PortableBinaryOutputArchive archive(filter);

	archive(data);
}

void read_cached_diff(const path &p, std::vector<uint8_t> &data)
{
	std::ifstream f(p.native(), std::ios::binary);
	filtering_istream filter;
	filter.push(lzma_decompressor());
	filter.push(f);

	cereal::PortableBinaryInputArchive archive(filter);

	archive(data);
}

int sign(char *private_key_file, char *file)
{
	if (!private_key_file) {
		fprintf(stderr, "error: <private_key_file> missing\n");
		return 1;
	}

	if (!file) {
		fprintf(stderr, "error: <file> missing\n");
		return 1;
	}

	path private_key_path(private_key_file);
	path file_path(file);

	if (!exists(private_key_path)) {
		fprintf(stderr, "error: <private_key_path> '%s' does not exist\n", private_key_path.generic_string().c_str());
		return 2;
	}

	if (!exists(file_path)) {
		fprintf(stderr, "error: <file> '%s' does not exist\n", file_path.generic_string().c_str());
		return 2;
	}

	std::vector<uint8_t> private_key_bytes;
	get_file_contents(private_key_path, file_size(private_key_path), private_key_bytes);
	std::string private_key((char *) private_key_bytes.data());

	private_key_bytes.resize(0);
	hex2bin(private_key, private_key_bytes);

	std::vector<uint8_t> file_contents;
	get_file_contents(file_path, file_size(file_path), file_contents);

	unsigned char sig[crypto_sign_BYTES];
	crypto_sign_detached(sig, NULL, file_contents.data(), file_contents.size(), private_key_bytes.data());

	std::string signature(bin2hex(sig));
	printf("%s\n", signature.c_str());

	return 0;
}

int keypair(char *private_key_file, char *public_key_file)
{
	if (!private_key_file) {
		fprintf(stderr, "error: <private_key_file> missing\n");
		return 1;
	}

	if (!public_key_file) {
		fprintf(stderr, "error: <public_key_file> missing\n");
		return 1;
	}

	path private_key_path(private_key_file);
	path public_key_path(public_key_file);

	if (exists(private_key_path)) {
		fprintf(stderr, "error: <private_key_path> '%s' already exists\n", private_key_path.generic_string().c_str());
		return 2;
	}

	if (exists(public_key_path)) {
		fprintf(stderr, "error: <public_key_path> '%s' already exists\n", public_key_path.generic_string().c_str());
		return 2;
	}

	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];

	printf("generating public and private key...");
	crypto_sign_keypair(pk, sk);

	std::string private_key(bin2hex(sk));
	std::string public_key(bin2hex(pk));

	set_file_contents(private_key_path, (uint8_t *)private_key.c_str(), private_key.length());
	set_file_contents(public_key_path, (uint8_t *)public_key.c_str(), public_key.length());

	return 0;
}

struct deferred_patch_info
{
	using patch_t = std::vector<uint8_t>*;
	size_t before_size, after_size;
	size_t max_patch_size;
	path before_path, after_path;
	path cache_path;
	patch_t patch;
	bool processing = false;
	bool done = false;

	deferred_patch_info(size_t before_size, size_t after_size, size_t max_patch_size,
			path before_path, path after_path, patch_t patch) :
		before_size(before_size), after_size(after_size), max_patch_size(max_patch_size),
		before_path(before_path), after_path(after_path), patch(patch)
	{
		patch->resize(max_patch_size + 1);
	}

	size_t max_mem_usage() const
	{
		return std::max(17 * before_size, 9 * before_size + after_size) + max_patch_size;
	}
};

template <typename T>
static inline T parse_val(char *string, T def)
{
	try
	{
		return string ? std::stoull(string) : def;
	}
	catch (const std::invalid_argument&)
	{}
	catch (const std::out_of_range&)
	{}

	return def;
}

int create(char *before_tree, char *after_tree, char *patch_file,
		char *threads, char *mem_limit, char *cache_dir)
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
	path cache_path;
	
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

	if (cache_dir && !is_directory(cache_path = absolute(cache_dir))) {
		fprintf(stderr, "error: [cache_dir] '%s' is not a directory", cache_path.generic_string().c_str());
		return 3;
	}

	const auto num_threads  = parse_val(threads, std::max(1u, std::thread::hardware_concurrency()));
	auto memory_limit = parse_val<size_t>(mem_limit, -1);
	if (memory_limit != -1)
		memory_limit *= 1024 * 1024;

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

	std::vector<deferred_patch_info> patch_infos;

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

			path cache_file_path = cache_path / before_info.hash / after_info.hash;
			if (!cache_path.empty() && exists(cache_file_path)) {
				read_cached_diff(cache_file_path, toc.ops.back().patch);
				continue;
			}

			size_t max_size = bsdiff_patchsize_max(before_info.size, after_info.size);
			patch_infos.emplace_back(before_info.size, after_info.size, max_size,
					before_path / i.first, after_path / i.first, &toc.ops.back().patch);

			if (!cache_path.empty())
				patch_infos.back().cache_path = cache_file_path;
		}
	}

	std::sort(begin(patch_infos), end(patch_infos),
			[](const deferred_patch_info &a, const deferred_patch_info &b) {
		return a.max_mem_usage() > b.max_mem_usage();
	});

	const size_t buffer_size = std::accumulate(begin(patch_infos), end(patch_infos), 0,
			[](size_t start, const deferred_patch_info &b) {
		return start + b.max_patch_size;
	});

	auto min_memory_limit = buffer_size + (patch_infos.empty() ? 0 : patch_infos.front().max_mem_usage());
	if (min_memory_limit > memory_limit) {
		fprintf(stderr, "warning: memory limit < required memory for largest patch: %u < %u",
				static_cast<unsigned>(memory_limit / 1024 / 1024),
				static_cast<unsigned>(min_memory_limit / 1024 / 1024 + 1));
		return 5;
	}

	printf("  %4d deletions\n  %4d additions\n  %4d bpatches (%d cached)\n",
			d_op_cnt, a_op_cnt, b_op_cnt, static_cast<int>(b_op_cnt - patch_infos.size()));

	size_t memory_used = buffer_size;
	std::mutex patch_info_mutex;
	std::condition_variable wake_threads;

	std::cout << "using " << num_threads << " threads (hw: " << std::thread::hardware_concurrency() << ")\n";
	std::vector<std::thread> patcher_threads;
	patcher_threads.reserve(num_threads);
	for (unsigned i = 0; i < num_threads && !patch_infos.empty(); i++) {
		patcher_threads.emplace_back([&]() {
			std::vector<uint8_t> p1_data;
			std::vector<uint8_t> p2_data;

			for (;;) {
				deferred_patch_info *work_item = nullptr;
				bool all_done = true;
				{
					auto lock = std::unique_lock<std::mutex>(patch_info_mutex);
					for (auto &info : patch_infos) {
						all_done = all_done && info.done;
						if (!info.done && !info.processing && info.max_mem_usage() < (memory_limit - memory_used)) {
							work_item = &info;
							break;
						}
					}
					if (work_item) {
						work_item->processing = true;
						memory_used += work_item->max_mem_usage();
					}
				}

				if (all_done)
					return;

				if (!work_item) {
					auto lock = std::unique_lock<std::mutex>(patch_info_mutex);
					wake_threads.wait(lock, [] { return true; });
					continue;
				}

				get_file_contents(work_item->before_path, work_item->before_size, p1_data);
				get_file_contents(work_item->after_path,  work_item->after_size,  p2_data);

				int actual_size = bsdiff(p1_data.data(), work_item->before_size,
						p2_data.data(), work_item->after_size, work_item->patch->data(),
						work_item->max_patch_size);
				work_item->patch->resize(actual_size);
				if (!work_item->cache_path.empty())
					write_cached_diff(work_item->cache_path, *work_item->patch);

				{

					auto lock = std::unique_lock<std::mutex>(patch_info_mutex);
					work_item->done = true;
					memory_used -= work_item->max_mem_usage();
				}
				wake_threads.notify_all();
			}
		});
	}

	for (auto &i : patcher_threads)
		i.join();

	std::ofstream ofs(patch_path.native(), std::ios::binary);
	filtering_ostream filter;
	filter.push(lzma_compressor({}, 4096));
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
			archive(i.patch);
			break;
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

	filter.push(lzma_decompressor());
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
			path p = after_path / i.path;
			if (i.ftype == file_type::directory_file) {
				create_directory(p);
				continue;
			}
			// symlink handling here
			archive(delta);
			set_file_contents(p, delta.data(), delta.size());
			continue;
		}
		case delta_op_type::PATCH: {
			path p = after_path / i.path;
			auto before_size = file_size(p);

			get_file_contents(p, before_size, before_file);
			archive(delta);
			auto after_size = bspatch_newsize(delta.data(), delta.size());		
			after_file.resize(after_size);
			int res = bspatch(before_file.data(), before_file.size(), delta.data(), delta.size(), after_file.data(), after_file.size());
			if (res != 0) {
				fprintf(stderr, "failed patching %s\n", p.generic_string().c_str());
			}
			set_file_contents(p, after_file.data(), after_file.size());
			continue;
		}
		case delta_op_type::DELETE:
			path p = after_path / i.path;
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
