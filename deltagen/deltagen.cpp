#include <cstring>
#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <fstream>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <numeric>

#include <boost/optional.hpp>
#include <boost/smart_ptr/shared_ptr.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/program_options.hpp>

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
#include "../util/scopeguard.hpp"
#include "../util/util.hpp"
#include <bscommon.h>

using namespace boost::iostreams;
namespace po = boost::program_options;

delta_info make_delta_info(const directory_entry &i)
{
	delta_info di;
	
	di.type = i.status().type();
	di.size = 0;
	if (is_regular_file(i.status()))
		di.size = file_size(i.path());
	hash_entry(i, di.hash);
	di.deleted = false;

	return di;
}

bool operator==(const delta_info &l, const delta_info &r) {
	return l.type == r.type && l.size == r.size && std::memcmp(l.hash, r.hash, sizeof(l.hash)) == 0;
}

static bool verbose;

int create(const path &before_path, const path &after_path, const path &patch_path,
	unsigned int num_threads, unsigned int memory_limit,
	const boost::optional<path> &cache_path, unsigned int lzma_preset);

int apply(const path &before_path, const path &patch_path);
int keypair(const path &secret_key_file, const path &public_key_file);
int sign(const path &secret_key_path, const path &file_path);

int remove_positional(po::options_description &op_desc, int pos_cnt)
{
	using namespace std;
	using options_t = remove_const<remove_reference<decltype(op_desc.options())>::type>::type;
	// remove last two arguments from help
	auto &ov = const_cast<options_t&>(op_desc.options());
	ov.resize(ov.size() - pos_cnt);
	return ov.size();
}

struct command {
	std::string name;
	std::string header;

	virtual int options(po::options_description &desc) = 0;
	virtual int handle(std::vector<std::string> &arguments, po::variables_map &vm) = 0;
	
	virtual void print_help() {
		po::options_description desc;
		int pos = options(desc);
		int rem = remove_positional(desc, pos);
		if (rem) { // Are there any non-positional options?
			std::cerr << name << ":" << std::endl;
			std::cerr << desc << std::endl;
		}
	}
};

struct apply_command : command {

	apply_command() {
		name = "apply";
		header = "apply <before_tree> <patch_file>";
	}

	int options(po::options_description &desc)
	{
		desc.add_options()
			("before", po::value<std::string>()->required(), "before tree")
			("patch", po::value<std::string>()->required(), "path to patch file");

		return 2;
	}

	int handle(std::vector<std::string> &arguments, po::variables_map &vm) {
		po::options_description desc;
		options(desc);

		po::positional_options_description pos;

		pos.add("before", 1);
		pos.add("patch", 1);

		po::store(po::command_line_parser(arguments).options(desc).positional(pos).run(), vm);
		po::notify(vm);

		return apply(
			vm["before"].as<std::string>(),
			vm["patch"].as<std::string>());
	}
};

struct create_command : command {

	create_command() {
		name = "create";
		header = "create <before_tree> <after_tree> <patch_file>";
	}

	int options(po::options_description &desc)
	{
		desc.add_options()
			("cache,c", po::value<std::string>(), "location for cache")
			("threads,t", po::value<unsigned int>()->default_value(std::max(1u, std::thread::hardware_concurrency())), "number of threads to use")
			("memory,m", po::value<int>()->default_value(-1), "memory limit")
			("lzma-preset,l", po::value<unsigned int>()->default_value(2), "lzma compression preset")
			("before", po::value<std::string>()->required(), "before tree (initial tree state)")
			("after", po::value<std::string>()->required(), "after tree (state to create after applying patch)")
			("patch", po::value<std::string>()->required(), "path to patch file being created");

		return 3;
	}

	int handle(std::vector<std::string> &arguments, po::variables_map &vm) {
		po::options_description desc;
		options(desc);
		
		po::positional_options_description pos;
		
		pos.add("before", 1);
		pos.add("after", 1);
		pos.add("patch", 1);

		po::store(po::command_line_parser(arguments).options(desc).positional(pos).run(), vm);
		po::notify(vm);

		boost::optional<path> cache;
		if (vm.count("cache"))
			cache = vm["cache"].as<std::string>();

		return create(
			vm["before"].as<std::string>(),
			vm["after"].as<std::string>(),
			vm["patch"].as<std::string>(),
			vm["threads"].as<unsigned int>(), 
			vm["memory"].as<int>(), 
			cache,
			vm["lzma-preset"].as<unsigned int>());
	}
};

struct keypair_command : command {

	keypair_command() {
		name = "keypair";
		header = "keypair <secret_key_file> <public_key_file>";
	}

	int options(po::options_description &desc)
	{
		desc.add_options()
			("secret_key", po::value<std::string>()->required(), "secret key file")
			("public_key", po::value<std::string>()->required(), "public key file");

		return 2;
	}

	int handle(std::vector<std::string> &arguments, po::variables_map &vm) {
		po::options_description desc;
		options(desc);

		po::positional_options_description pos;

		pos.add("secret_key", 1);
		pos.add("public_key", 1);

		po::store(po::command_line_parser(arguments).options(desc).positional(pos).run(), vm);
		po::notify(vm);

		return keypair(
			vm["secret_key"].as<std::string>(),
			vm["public_key"].as<std::string>());
	}
};

struct sign_command : command {

	sign_command() {
		name = "sign";
		header = "sign <secret_key_file> <file>";
	}

	int options(po::options_description &desc)
	{
		desc.add_options()
			("secret_key", po::value<std::string>()->required(), "secret key file")
			("file", po::value<std::string>()->required(), "file to sign");

		return 2;
	}

	int handle(std::vector<std::string> &arguments, po::variables_map &vm) {
		po::options_description desc;
		options(desc);

		po::positional_options_description pos;

		pos.add("secret_key", 1);
		pos.add("file", 1);

		po::store(po::command_line_parser(arguments).options(desc).positional(pos).run(), vm);
		po::notify(vm);

		return sign(
			vm["secret_key"].as<std::string>(),
			vm["file"].as<std::string>());
	}
};

int show_help(int result, std::string &bn, po::options_description &desc, std::map<std::string, command*> commands) {

	remove_positional(desc, 2);

	if (result == 1) {
		std::cerr << "usage: " << bn << " <command> <args>" << std::endl;
		std::cerr << "Commands:" << std::endl;
		std::cerr << "  help" << std::endl;
		for (auto &i : commands) {
			std::cerr << "  " << i.second->header << std::endl;
		}
		std::cerr << std::endl;
		std::cerr << desc << std::endl;
		for (auto &i : commands) {
			i.second->print_help();
		}
	}

	return result;
}

int main(int argc, const char *argv[])
{
	
	std::string bn = basename(path(argv[0]));

	apply_command apply_cmd;
	create_command create_cmd;
	keypair_command keypair_cmd;
	sign_command sign_cmd;

	std::map<std::string, command*> commands = {
			{ apply_cmd.name, &apply_cmd },
			{ create_cmd.name, &create_cmd },
			{ keypair_cmd.name, &keypair_cmd },
			{ sign_cmd.name, &sign_cmd },
	};
	
	int result = 0;

	po::options_description op_desc("Options");
	op_desc.add_options()
		("verbose,v", po::bool_switch()->default_value(false), "enable verbose execution")
		("command", po::value<std::string>()->default_value("help"), "command to execute")
		("arguments", po::value<std::vector<std::string> >(), "arguments for command");


	po::positional_options_description pos_desc;
	pos_desc.add("command", 1);
	pos_desc.add("arguments", -1);

	po::variables_map vm;
	
	try {
		auto p = po::command_line_parser(argc, argv)
			.options(op_desc)
			.positional(pos_desc)
			.allow_unregistered()
			.run();

		po::store(p, vm);
		po::notify(vm);

		std::string cmd_string = vm["command"].as<std::string>();

		if (cmd_string == "help") {
			return show_help(1, bn, op_desc, commands);
		}

		auto cmd = commands.find(cmd_string);
		if (cmd == end(commands)) {
			throw po::invalid_option_value(cmd_string);
		}

		verbose = vm["verbose"].as<bool>();

		std::vector<std::string> args = po::collect_unrecognized(p.options, po::include_positional);
		args.erase(args.begin());

		result = cmd->second->handle(args, vm);
		
	}
	catch (po::error &e) {
		std::cerr << "error: " << e.what() << std::endl << std::endl;
		result = 1;
	}

	return show_help(result, bn, op_desc, commands);
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

void write_cached_diff(const path &p, const std::vector<uint8_t> &data)
{
	path tmp = unique_path();
	std::ofstream f(tmp.native(), std::ios::binary | std::ios::trunc);

	filtering_ostream filter;
	filter.push(lzma_compressor({}, 4096));
	filter.push(f);

	cereal::PortableBinaryOutputArchive archive(filter);

	archive(data);

	create_directories(p.parent_path());
	rename(tmp, p);
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

int sign(const path &secret_key_path, const path &file_path)
{
	if (!exists(secret_key_path)) {
		std::cerr << "error: <secret_key_file> '" << secret_key_path.generic_string() << "' does not exist" << std::endl;
		return 2;
	}

	if (!exists(file_path)) {
		std::cerr << "error: <file> '" << file_path.generic_string() << "' does not exist" << std::endl;
		return 2;
	}

	std::vector<uint8_t> secret_key_bytes;
	sporkel_util::get_file_contents(secret_key_path, file_size(secret_key_path), secret_key_bytes);
	std::string secret_key((char *) secret_key_bytes.data());

	secret_key_bytes.resize(0);
	hex2bin(secret_key, secret_key_bytes);

	std::vector<uint8_t> file_contents;
	sporkel_util::get_file_contents(file_path, file_size(file_path), file_contents);

	unsigned char sig[crypto_sign_BYTES];
	crypto_sign_detached(sig, NULL, file_contents.data(), file_contents.size(), secret_key_bytes.data());

	std::string signature(bin2hex(sig));
	printf("%s\n", signature.c_str());

	return 0;
}

int keypair(const path &secret_key_path, const path &public_key_path)
{
	if (exists(secret_key_path)) {
		std::cerr << "error: <secret_key_path> '" << secret_key_path.generic_string() << "' already exists" << std::endl;
		return 2;
	}

	if (exists(public_key_path)) {
		std::cerr << "error: <public_key_path> '" << public_key_path.generic_string() << "' already exists" << std::endl;
		return 2;
	}

	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];

	printf("generating public and secret key...");
	crypto_sign_keypair(pk, sk);

	std::string secret_key(bin2hex(sk));
	std::string public_key(bin2hex(pk));

	sporkel_util::set_file_contents(secret_key_path, (uint8_t *) secret_key.c_str(), secret_key.length());
	sporkel_util::set_file_contents(public_key_path, (uint8_t *) public_key.c_str(), public_key.length());

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
		return (sizeof(off_t) + 1) * before_size + 3 * after_size;
	}
};

int create(const path &before_path, const path &after_path, const path &patch_path,
		unsigned int num_threads, unsigned int memory_limit, const boost::optional<path> &cache_path,
		unsigned int lzma_preset)
{

	if (!is_directory(before_path)) {
		std::cerr << "error: <before_tree> '" << before_path.generic_string() << "' is not a directory" << std::endl;
		return 1;
	}

	if (!is_directory(after_path)) {
		std::cerr << "error: <after_tree> option '" << after_path.generic_string() << "' is not a directory" << std::endl;
		return 1;
	}

	if (exists(patch_path)) {
		std::cerr << "error: <patch_file> '" << patch_path.generic_string() << "' already exists" << std::endl;
		return 2;
	}

	if (cache_path && !is_directory(cache_path.get())) {
		std::cerr << "error: [cache_dir] '" << cache_path.get().generic_string() << "' is not a directory" << std::endl;
		return 3;
	}

	if (memory_limit != std::numeric_limits<unsigned int>::max())
		memory_limit *= 1024 * 1024;

	std::map<std::string, delta_info> before_tree_state;
	std::map<std::string, delta_info> after_tree_state_unmod;
	std::map<std::string, delta_info> after_tree_state;

	delta_info deleted;
	deleted.deleted = true;

	delta_op_toc toc;

	printf("processing %s...\n", before_path.generic_string().c_str());
	std::thread before_thread([&] {
		process_tree(before_path, [&](path &path, const directory_entry &i) {
			auto before_info = make_delta_info(i);
			auto key(path.generic_string());
			before_tree_state.emplace(key, std::move(before_info));
			after_tree_state.emplace(std::move(key), deleted);
		});

		toc.before_hash = get_tree_hash(before_tree_state);
	});

	printf("processing %s...\n", after_path.generic_string().c_str());
	std::thread after_thread([&] {
		process_tree(after_path, [&](path &path, const directory_entry &i) {
			auto after_info = make_delta_info(i);
			auto key(path.generic_string());
			after_tree_state_unmod.emplace(std::move(key), std::move(after_info));
		});

		toc.after_hash = get_tree_hash(after_tree_state_unmod);
	});

	before_thread.join();
	after_thread.join();

	for (auto &after : after_tree_state_unmod) {
		auto &key  = after.first;
		auto &info = after.second;

		auto res = before_tree_state.find(key);
		if (res != end(before_tree_state)) {
			if (res->second == info) {
				after_tree_state.erase(key);
				continue;
			}
		}

		after_tree_state[key] = info;
	}

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

	toc.ops.reserve(after_tree_state.size() * 2);
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

			boost::optional<path> cache_file_path;
			if (cache_path)
				cache_file_path = cache_path.get() / bin2hex(before_info.hash) / bin2hex(after_info.hash);

			if (cache_file_path && exists(cache_file_path.get())) {
				read_cached_diff(cache_file_path.get(), toc.ops.back().patch);
				continue;
			}

			size_t max_size = bsdiff_patchsize_max(before_info.size, after_info.size);
			patch_infos.emplace_back(before_info.size, after_info.size, max_size,
				before_path / i.first, after_path / i.first, &toc.ops.back().patch);

			if (cache_file_path)
				patch_infos.back().cache_path = cache_file_path.get();
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

	printf("memory required: %u MB\n", static_cast<unsigned>(min_memory_limit / 1024 / 1024 + 1));
	if (memory_limit != -1)
		printf("memory limit: %u MB\n", static_cast<unsigned>(memory_limit / 1024 / 1024));

	if (min_memory_limit > memory_limit) {
		fprintf(stderr, "error: memory limit < required memory for largest patch");
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

				sporkel_util::get_file_contents(work_item->before_path,
						work_item->before_size, p1_data);
				sporkel_util::get_file_contents(work_item->after_path,
						work_item->after_size, p2_data);

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
	filter.push(lzma_compressor(lzma_params(lzma_preset)), 4096);
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
			sporkel_util::get_file_contents(p, s, delta);
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

int apply(const path &before_path, const path &patch_path)
{
	if (!is_directory(before_path)) {
		std::cerr << "error: <before_tree> '" << before_path.generic_string() << "' is not a directory" << std::endl;
		return 1;
	}

	if (!exists(patch_path) || !is_regular_file(patch_path)) {
		std::cerr << "error: <patch_file> '" << patch_path.generic_string() << "' does not exist or not a file" << std::endl;
		return 2;
	}

	const path after_path(get_temp_directory());

	printf("copying %s to %s...\n", before_path.generic_string().c_str(), after_path.generic_string().c_str());

	copy_directory_recursive(before_path, after_path);
	DEFER{ remove_all(after_path); };

	std::ifstream ifs(patch_path.native(), std::ios::binary);
	filtering_istream filter;

	filter.push(lzma_decompressor());
	filter.push(ifs);

	delta_op_toc toc;

	cereal::PortableBinaryInputArchive archive(filter);
	archive(toc);

	printf("validating tree initial state %s...\n", after_path.generic_string().c_str());

	std::map<std::string, delta_info> before_tree_state;
	process_tree(before_path, [&](path &path, const directory_entry &i) {
		before_tree_state[path.generic_string()] = make_delta_info(i);
	});

	std::string before_tree_hash = get_tree_hash(before_tree_state);
	if (before_tree_hash != toc.before_hash) {
		fprintf(stderr, "error: current tree hash %s does not match the expected tree hash %s\n", 
				before_tree_hash.c_str(), toc.before_hash.c_str());
		return 2;
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
			sporkel_util::set_file_contents(p, delta.data(), delta.size());
			continue;
		}
		case delta_op_type::PATCH: {
			path p = after_path / i.path;
			auto before_size = file_size(p);

			sporkel_util::get_file_contents(p, before_size, before_file);
			archive(delta);
			auto after_size = bspatch_newsize(delta.data(), delta.size());
			after_file.resize(after_size);
			int res = bspatch(before_file.data(), before_file.size(), delta.data(), delta.size(), after_file.data(), after_file.size());
			if (res != 0) {
				fprintf(stderr, "failed patching %s\n", p.generic_string().c_str());
			}
			sporkel_util::set_file_contents(p, after_file.data(), after_file.size());
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
	process_tree(after_path, [&](path &path, const directory_entry &i) {
		after_tree_state[path.generic_string()] = make_delta_info(i);
	});

	std::string after_tree_hash = get_tree_hash(after_tree_state);
	if (after_tree_hash != toc.after_hash) {
		fprintf(stderr, "error: patched tree hash %s does not match the expected tree hash %s\n",
			after_tree_hash.c_str(), toc.after_hash.c_str());
		return 2;
	}

	return 0;
}
