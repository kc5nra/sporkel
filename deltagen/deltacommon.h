#pragma once

#include <functional>
#include <boost/filesystem.hpp>
#include <string>
#include <sodium.h>

#include <cereal/cereal.hpp>
#include <cereal/access.hpp>

using namespace boost::filesystem;

struct delta_info
{
	std::string hash;
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

	delta_op() = default;
	delta_op(delta_op_type type, const std::string &path) : type(type), path(path) {}
	
private:
	friend class cereal::access;
	template<class Archive>
	void serialize(Archive &ar, const unsigned int version)
	{
		switch (version) {
		case 1:
			ar(type, path);
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
std::string hash_entry(recursive_directory_iterator &i);
void hash_entry(recursive_directory_iterator &i, crypto_generichash_state &state);

path make_path_relative(path &a_From, path &a_To);

path get_temp_directory();
