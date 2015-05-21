#pragma once

#include <functional>
#include <boost/filesystem.hpp>
#include <string>
#include <sodium.h>

#include <cereal/cereal.hpp>
#include <cereal/access.hpp>

#include "../../util/util.hpp"

using namespace boost::filesystem;

struct delta_info
{
	unsigned char hash[crypto_generichash_BYTES];
	file_type type;
	unsigned long long size;
	bool deleted;
};

bool operator==(const delta_info &a, const delta_info &b);

enum delta_op_type 
{
	DELETE,
	ADD,
	PATCH
};

struct delta_op 
{
	delta_op_type type;
	std::string path;
	file_type ftype;
	std::vector<uint8_t> patch;

	delta_op() = default;
	delta_op(delta_op_type type, const std::string &path, file_type ftype) 
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
CEREAL_CLASS_VERSION(delta_op, 1);

struct delta_op_toc 
{
	std::vector<delta_op> ops;
	std::string before_hash;
	std::string after_hash;

private:
	friend class cereal::access;
	template<class Archive>
	void serialize(Archive &ar, const unsigned int version)
	{
		switch (version) {
		case 1:
			ar(ops, before_hash, after_hash);
			break;
		default:
			throw cereal::Exception("unknown version");
		}
	}
}; 
CEREAL_CLASS_VERSION(delta_op_toc, 1);

void process_tree(path &p, std::function<void(path &p, recursive_directory_iterator &i)> f);

void hash_delta_info(const std::string &path, const delta_info &di, crypto_generichash_state &state);
void hash_entry(const directory_entry &i, unsigned char(&hash)[crypto_generichash_BYTES]);
void hash_entry(const directory_entry &i, crypto_generichash_state &state);

path get_temp_directory();

template <typename Func>
void process_tree(const path &p, Func &&f) //std::function<void(path &path, recursive_directory_iterator &i)> f)
{
	recursive_directory_iterator end;
	for (recursive_directory_iterator i(p); i != end; ++i) {
		file_type type = i->status().type();
		if (!is_directory(i->status()) && !is_regular_file(i->status()) && !is_symlink(i->status())) {
			continue;
		}

		path rel_path(sporkel_util::make_path_relative(p, i->path()));
		if (!rel_path.empty())
			f(rel_path, *i);
	}
}

template <size_t N, typename T>
std::string bin2hex(T(&data)[N])
{
	char hex[N * 2 + 1];
	sodium_bin2hex(hex, N * 2 + 1, static_cast<unsigned char *>(data), N);
	return hex;
}

void hex2bin(const std::string &hex, std::vector<unsigned char> &bin);
