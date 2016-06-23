#include "../include/sporkel.h"

#include <condition_variable>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <numeric>
#include <string>
#include <thread>
#include <iostream>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/lzma.hpp>
#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include <cereal/access.hpp>
#include <cereal/archives/binary.hpp>
#include <cereal/archives/portable_binary.hpp>
#include <cereal/cereal.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/string.hpp>

#include <sodium.h>

#include <bscommon.h>

#include "../../util/util.hpp"
#include "../../util/scopeguard.hpp"

namespace fs = boost::filesystem;
namespace io = boost::iostreams;

namespace {
	struct delta_info {
		unsigned char hash[crypto_generichash_BYTES];
		fs::file_type type;
		unsigned long long size;
		bool deleted;
	};

	enum class delta_op_type 
	{
		DELETE,
		ADD,
		PATCH,
		KEEP
	};

	struct delta_op {
		delta_op_type type;
		std::string path;
		fs::file_type ftype;
		std::vector<uint8_t> patch;

		delta_op() = default;
		delta_op(delta_op_type type, const std::string &path, fs::file_type ftype) 
			: type(type), path(path), ftype(ftype) {}
		
	private:
		friend class cereal::access;
		template<class Archive>
		void serialize(Archive &ar, const unsigned int version)
		{
			switch (version) {
			case 1:
				ar(type, path, ftype);
				break;
			default:
				throw cereal::Exception("unknown version");
			}
		}
	}; 

	struct delta_op_toc {
		std::vector<delta_op> ops;
		std::string before_hash;
		std::string after_hash;
		bool require_exact_patch_target = false;

	private:
		friend class cereal::access;
		template<class Archive>
		void serialize(Archive &ar, const unsigned int version)
		{
			switch (version) {
			case 2:
				ar(ops, before_hash, after_hash, require_exact_patch_target);
				break;
			case 1:
				ar(ops, before_hash, after_hash);
				break;
			default:
				throw cereal::Exception("unknown version");
			}
		}
	};

	struct deferred_patch_info
	{
		using patch_t = std::vector<uint8_t>*;
		size_t before_size, after_size;
		size_t max_patch_size;
		fs::path before_path, after_path;
		fs::path cache_path;
		patch_t patch;
		bool processing = false;
		bool done = false;

		deferred_patch_info(size_t before_size, size_t after_size, size_t max_patch_size,
				fs::path before_path, fs::path after_path, patch_t patch) :
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
}

CEREAL_CLASS_VERSION(delta_op, 1);
CEREAL_CLASS_VERSION(delta_op_toc, 2);

static void hash_delta_info(const std::string &path, const delta_info &di, crypto_generichash_state &state);
static void hash_entry(const fs::directory_entry &i, unsigned char(&hash)[crypto_generichash_BYTES]);
static void hash_entry(const fs::directory_entry &i, crypto_generichash_state &state);

static bool operator==(const delta_info &l, const delta_info &r) {
	return l.type == r.type && l.size == r.size && std::memcmp(l.hash, r.hash, sizeof(l.hash)) == 0;
}

static void hash_delta_info(const std::string &p, const delta_info &di, crypto_generichash_state &state)
{
	crypto_generichash_update(&state, (const unsigned char *) p.c_str(), p.length());
	crypto_generichash_update(&state, (const unsigned char *) &di.type, sizeof(decltype(di.type)));
	crypto_generichash_update(&state, (const unsigned char *) &di.size, sizeof(decltype(di.size)));
	crypto_generichash_update(&state, di.hash, sizeof(di.hash));
}

static void hash_entry(const fs::directory_entry &i, crypto_generichash_state &state)
{
	using namespace fs;

	auto &p = i.path();
	size_t size = 0;
	if (is_regular_file(i.status()))
		size = (size_t)file_size(i.path());

	if (is_regular(i.status())) {

		char chunk_buffer[16 * 1024];
		size_t chunk_buffer_size = sizeof(chunk_buffer);
		size_t chunk_cnt = size / chunk_buffer_size;
		size_t last_chunk_size = size % chunk_buffer_size;

		std::ifstream file(p.native(), std::ifstream::binary);

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

	if (is_symlink(i.status())) {
		path sym_path(fs::read_symlink(p));
		std::string s = sym_path.generic_string();
		crypto_generichash_update(&state, (unsigned char *) s.c_str(), s.length());
		return;
	}

	if (is_directory(i.status())) {
		crypto_generichash_update(&state, (const unsigned char *)"d", 1);
		return;
	}
}

static void hash_entry(const fs::directory_entry &i, unsigned char (&hash)[crypto_generichash_BYTES])
{
	crypto_generichash_state state;

	crypto_generichash_init(&state, NULL, 0, sizeof(hash));
	hash_entry(i, state);
	crypto_generichash_final(&state, hash, sizeof(hash));
}

static fs::path get_temp_directory()
{
	using namespace fs;
	path p(unique_path());
	return temp_directory_path() / p;
}

template <typename Func>
static void process_tree(const fs::path &p, Func &&f)
{
	using namespace fs;
	recursive_directory_iterator end;
	for (recursive_directory_iterator i(p); i != end; ++i) {
		if (!is_directory(i->status()) && !is_regular_file(i->status()) && !is_symlink(i->status())) {
			continue;
		}

		path rel_path(sporkel_util::make_path_relative(p, i->path()));
		if (!rel_path.empty())
			f(rel_path, *i);
	}
}

template <size_t N, typename T>
static std::string bin2hex(T(&data)[N])
{
	char hex[N * 2 + 1];
	sodium_bin2hex(hex, N * 2 + 1, static_cast<unsigned char *>(data), N);
	return hex;
}

static delta_info make_delta_info(const fs::directory_entry &i)
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

static std::string get_tree_hash(const std::map<std::string, delta_info> &tree)
{
	unsigned char hash[crypto_generichash_BYTES];
	crypto_generichash_state state;
	crypto_generichash_init(&state, NULL, 0, sizeof(hash));
	for (auto &i : tree) {
		hash_delta_info(i.first, i.second, state);
	}
	crypto_generichash_final(&state, hash, sizeof(hash));
	return bin2hex(hash);
}

struct sporkel_tmp_dir {
	fs::path    path;
	std::string generic_string;

	sporkel_tmp_dir()
		: path(get_temp_directory()),
		  generic_string(path.generic_string())
	{}
};

sporkel_tmp_dir_t *sporkel_tmp_dir_create(void)
{
	try {
		return new sporkel_tmp_dir_t();
	} catch (...) {
		return nullptr;
	}
}

void sporkel_tmp_dir_destroy(sporkel_tmp_dir_t *dir)
{
	delete dir;
}

const char *sporkel_tmp_dir_path(const sporkel_tmp_dir_t *dir)
{
	return dir->generic_string.c_str();
}

#define sporklog(cb, l, x) do { if (cb == nullptr || cb->log_cb == nullptr) break; std::stringstream s; s << x; cb->log_cb(cb->log_data, l, s.str().c_str()); } while (0)
#define spklogd(cb, x) sporklog(cb, SPORKEL_DEBUG, x)
#define spklogi(cb, x) sporklog(cb, SPORKEL_INFO, x)
#define spklogw(cb, x) sporklog(cb, SPORKEL_WARNING, x)
#define spkloge(cb, x) sporklog(cb, SPORKEL_ERROR, x)

static bool sporkel_patch_apply_internal(fs::path before_path, std::istream &is, fs::path dest,
		bool remove_if_failed, sporkel_callback_t *cb);

bool sporkel_patch_apply(const char *before_path_, const char *patch_path_, const char *dest_,
		bool remove_if_failed, sporkel_callback_t *cb)
{
	try {
		fs::path patch_path(patch_path_);
		fs::path dest(dest_);

		std::ifstream ifs(patch_path.native(), std::ios::binary);
		return sporkel_patch_apply_internal(before_path_, ifs, dest, remove_if_failed, cb);
	} catch (...) {
		return false;
	}
}

static bool sporkel_patch_apply_internal(fs::path before_path, std::istream &is, fs::path dest,
		bool removed_if_failed, sporkel_callback_t *cb)
{
	using namespace fs;
	using namespace io;

	if (before_path.empty() && dest.empty()) {
		spkloge(cb, "before_path and dest are empty");
		return false;
	}

	bool target_copied = !(before_path.empty() || dest.empty() || before_path == dest);

	if (target_copied) {
		spklogi(cb, "copying " << before_path.generic_string() << " to " << dest.generic_string());
		sporkel_util::copy_directory_recursive(before_path, dest);
	}

	bool patch_failed = true;
	DEFER{
		if (removed_if_failed && patch_failed && target_copied) {
			spklogi(cb, "removing " << dest.generic_string() << "...");
			remove_all(dest);
		}
	};

	if (before_path.empty())
		before_path = dest;
	if (dest.empty())
		dest = before_path;

	filtering_istream filter;

	filter.push(lzma_decompressor());
	filter.push(is);

	delta_op_toc toc;

	cereal::PortableBinaryInputArchive archive(filter);
	archive(toc);

	spklogi(cb, "validating tree initial state " << dest.generic_string() << "...");

	std::map<std::string, delta_info> before_tree_state;
	process_tree(before_path, [&](path &path, const directory_entry &i) {
		before_tree_state[path.generic_string()] = make_delta_info(i);
	});

	std::string before_tree_hash;
	if (toc.require_exact_patch_target)
		before_tree_hash = get_tree_hash(before_tree_state);
	else {
		std::map<std::string, delta_info> before_tree_state_mod;
		for (auto &i : toc.ops) {
			if (i.type == delta_op_type::ADD)
				continue;
			
			auto res = before_tree_state.find(i.path);
			if (res == end(before_tree_state)) {
				spkloge(cb, "patch contains non-ADD op for non-existing file " << i.path);
				return false;
			}

			before_tree_state_mod.emplace(*res);
			//spklogi(cb, res->first << ": " << bin2hex(res->second.hash));
		}
		before_tree_hash = get_tree_hash(before_tree_state_mod);
	}

	if (before_tree_hash != toc.before_hash) {
		spkloge(cb, "current tree hash " << before_tree_hash << " does not match the expected tree hash " <<
				toc.before_hash);
		return false;
	}

	spklogi(cb, "applying patches...");

	std::vector<uint8_t> delta;
	std::vector<uint8_t> before_file;
	std::vector<uint8_t> after_file;

	const size_t total = toc.ops.size();
	size_t completed = 0;
	for (auto &i : toc.ops) {
		switch (i.type) {
		case delta_op_type::ADD:
		{
			path p = dest / i.path;
			if (i.ftype == file_type::directory_file) {
				create_directory(p);
				break;
			}
			// symlink handling here
			archive(delta);
			sporkel_util::set_file_contents(p, delta.data(), delta.size());
			break;
		}
		case delta_op_type::PATCH:
		{
			path p = dest / i.path;
			auto before_size = file_size(p);

			sporkel_util::get_file_contents(p, before_size, before_file);
			archive(delta);
			auto after_size = sporkel_bspatch_newsize(delta.data(), delta.size());
			after_file.resize(after_size);
			int res = sporkel_bspatch(before_file.data(), before_file.size(), delta.data(), delta.size(), after_file.data(), after_file.size());
			if (res != 0) {
				spkloge(cb, "failed patching " << p.generic_string());
			}
			sporkel_util::set_file_contents(p, after_file.data(), after_file.size());
			break;
		}
		case delta_op_type::KEEP:
			break;
		case delta_op_type::DELETE:
			path p = dest / i.path;
			remove_all(p);
			break;
		}
		if (cb != nullptr && cb->progress_cb != nullptr)
			cb->progress_cb(cb->progress_data, ++completed, total);
	}

	spklogi(cb, "validating tree patched state " << dest.generic_string() << "...");

	std::map<std::string, delta_info> after_tree_state;
	process_tree(dest, [&](path &path, const directory_entry &i) {
		after_tree_state[path.generic_string()] = make_delta_info(i);
	});

	std::string after_tree_hash = get_tree_hash(after_tree_state);
	if (toc.require_exact_patch_target)
		after_tree_hash = get_tree_hash(after_tree_state);
	else {
		delta_info deleted;
		deleted.deleted = true;

		std::map<std::string, delta_info> after_tree_state_mod;
		for (auto &i : toc.ops) {
			switch (i.type) {
			case delta_op_type::ADD:
			case delta_op_type::PATCH:
			case delta_op_type::KEEP:
				after_tree_state_mod.emplace(i.path, after_tree_state[i.path]);
				break;

			case delta_op_type::DELETE:
				after_tree_state_mod[i.path] = deleted;
			}
		}
		after_tree_hash = get_tree_hash(after_tree_state_mod);
	}

	if (after_tree_hash != toc.after_hash) {
		spkloge(cb, "patched tree hash " << after_tree_hash <<
				" does not match the expected tree hash " << toc.after_hash);
		return false;
	}

	patch_failed = false;
	return true;
}

static void write_cached_diff(const fs::path &p, const std::vector<uint8_t> &data)
{
	fs::path tmp = fs::unique_path();
	std::ofstream f(tmp.native(), std::ios::binary | std::ios::trunc);

	io::filtering_ostream filter;
	filter.push(io::lzma_compressor({}, 4096));
	filter.push(f);

	cereal::PortableBinaryOutputArchive archive(filter);

	archive(data);

	create_directories(p.parent_path());
	rename(tmp, p);
}

static void read_cached_diff(const fs::path &p, std::vector<uint8_t> &data)
{
	std::ifstream f(p.native(), std::ios::binary);
	io::filtering_istream filter;
	filter.push(io::lzma_decompressor());
	filter.push(f);

	cereal::PortableBinaryInputArchive archive(filter);

	archive(data);
}

static bool sporkel_patch_create_internal(fs::path before_path, fs::path after_path, fs::path patch_path,
		unsigned num_threads, unsigned memory_limit, boost::optional<fs::path> cache_path, unsigned lzma_preset,
		bool require_exact_patch_target,
		sporkel_callback_t *cb);

bool sporkel_patch_create(const char *before_path, const char *after_path, const char *patch_path,
		unsigned num_threads, unsigned memory_limit, const char *cache_path,
		unsigned lzma_preset,
		bool require_exact_patch_target,
		sporkel_callback_t *cb)
{
	try {
		boost::optional<fs::path> cache;
		if (cache_path)
			cache = cache_path;

		return sporkel_patch_create_internal(before_path, after_path, patch_path,
				num_threads, memory_limit, cache, lzma_preset, require_exact_patch_target, cb);
	} catch (...) {
		return false;
	}
}

static bool sporkel_patch_create_internal(fs::path before_path, fs::path after_path, fs::path patch_path,
		unsigned num_threads, unsigned memory_limit, boost::optional<fs::path> cache_path, unsigned lzma_preset,
		bool require_exact_patch_target,
		sporkel_callback_t *cb)
{
	using namespace fs;
	using namespace io;

	if (memory_limit != std::numeric_limits<unsigned int>::max())
		memory_limit = std::max(memory_limit, memory_limit * 1024 * 1024);

	std::map<std::string, delta_info> before_tree_state;
	std::map<std::string, delta_info> after_tree_state_unmod;
	std::map<std::string, delta_info> after_tree_state;
	std::map<std::string, delta_info> before_tree_state_mod;

	delta_info deleted;
	deleted.deleted = true;

	delta_op_toc toc;

	spklogi(cb, "processing " << before_path.generic_string() << "...");
	std::thread before_thread([&] {
		process_tree(before_path, [&](path &path, const directory_entry &i) {
			auto before_info = make_delta_info(i);
			auto key(path.generic_string());
			before_tree_state.emplace(key, std::move(before_info));
			after_tree_state.emplace(std::move(key), deleted);
		});

		if (require_exact_patch_target)
			toc.before_hash = get_tree_hash(before_tree_state);
	});

	if (num_threads == 1)
		before_thread.join();

	spklogi(cb, "processing " << after_path.generic_string() << "...");
	std::thread after_thread([&] {
		process_tree(after_path, [&](path &path, const directory_entry &i) {
			auto after_info = make_delta_info(i);
			auto key(path.generic_string());
			after_tree_state_unmod.emplace(std::move(key), std::move(after_info));
		});

		if (require_exact_patch_target)
			toc.after_hash = get_tree_hash(after_tree_state_unmod);
	});

	if (before_thread.joinable())
		before_thread.join();
	after_thread.join();

	for (auto &after : after_tree_state_unmod) {
		auto &key  = after.first;
		auto &info = after.second;

		auto res = before_tree_state.find(key);
		if (require_exact_patch_target && res != end(before_tree_state)) {
			if (res->second == info) {
				after_tree_state.erase(key);
				continue;
			}
		}

		after_tree_state[key] = info;

		if (res == end(before_tree_state))
			continue;

		before_tree_state_mod.emplace(*res);
		//spklogi(cb, res->first << ": " << bin2hex(res->second.hash));
	}

	if (!require_exact_patch_target) {
		toc.before_hash = get_tree_hash(before_tree_state_mod);
		toc.after_hash = get_tree_hash(after_tree_state);
		toc.require_exact_patch_target = require_exact_patch_target;
	}

	spklogi(cb, "before tree: '" << before_path.generic_string() << "'");
	spklogi(cb, "    hash: '" << toc.before_hash << "'");
	spklogi(cb, "    file count: " << before_tree_state.size());
	spklogi(cb, "after tree: '" << after_path.generic_string() << "'");
	spklogi(cb, "    hash: '" << toc.after_hash << "'");
	spklogi(cb, "    mod cnt: " << after_tree_state.size());

	spklogi(cb, "generating delta operations...");

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
		if (!require_exact_patch_target && before_info == after_info) {
			toc.ops.emplace_back(delta_op_type::KEEP, i.first, after_info.type);
			continue;
		}

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
				cache_file_path = cache_path.get() / i.first / bin2hex(before_info.hash) / bin2hex(after_info.hash);

			if (cache_file_path && exists(cache_file_path.get())) {
				read_cached_diff(cache_file_path.get(), toc.ops.back().patch);
				continue;
			}

			size_t max_size = sporkel_bsdiff_patchsize_max(before_info.size, after_info.size);
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

	spklogi(cb, "memory required: " << static_cast<unsigned>(min_memory_limit / 1024 / 1024 + 1) << " MB\n");
	if (memory_limit != std::numeric_limits<unsigned int>::max())
		spklogi(cb, "memory limit: " << static_cast<unsigned>(memory_limit / 1024 / 1024) << " MB\n");

	if (min_memory_limit > memory_limit) {
		spkloge(cb, "memory limit < required memory for largest patch");
		return false;
	}

	spklogi(cb, d_op_cnt << " deletions");
	spklogi(cb, a_op_cnt << " additions");
	spklogi(cb, b_op_cnt << " bpatches (" << static_cast<int>(b_op_cnt - patch_infos.size()) << " cached)");

	size_t memory_used = buffer_size;
	std::mutex patch_info_mutex;
	std::condition_variable wake_threads;

	spklogi(cb, "using " << num_threads << " threads (hw: " << std::thread::hardware_concurrency() << ")");
	std::vector<std::thread> patcher_threads;
	patcher_threads.reserve(num_threads);
	const size_t total = patch_infos.size();
	size_t completed = 0;
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

				sporkel_util::get_file_contents(work_item->before_path, work_item->before_size, p1_data);
				sporkel_util::get_file_contents(work_item->after_path, work_item->after_size, p2_data);

				int actual_size = sporkel_bsdiff(p1_data.data(), work_item->before_size,
					p2_data.data(), work_item->after_size, work_item->patch->data(),
					work_item->max_patch_size);
				work_item->patch->resize(actual_size);
				if (!work_item->cache_path.empty())
					write_cached_diff(work_item->cache_path, *work_item->patch);

				{

					auto lock = std::unique_lock<std::mutex>(patch_info_mutex);
					work_item->done = true;
					memory_used -= work_item->max_mem_usage();
					if (cb != nullptr && cb->progress_cb != nullptr)
						cb->progress_cb(cb->progress_data, ++completed, total);
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
		case delta_op_type::KEEP:
		case delta_op_type::DELETE:
			break;
		}
	}

	return true;
}

#undef sporklog
#undef spklogd
#undef spklogi
#undef spklogw
#undef spkloge

