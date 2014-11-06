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
	file_type ftype;

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
std::string hash_entry(recursive_directory_iterator &i);
void hash_entry(recursive_directory_iterator &i, crypto_generichash_state &state);

path make_path_relative(path &a_From, path &a_To);

path get_temp_directory();
path make_path_relative(path a_From, path a_To);
bool copy_directory_recursive(const path &from, const path &to);

template <typename Func>
void process_tree(path &p, Func &&f) //std::function<void(path &path, recursive_directory_iterator &i)> f)
{
	recursive_directory_iterator end;
	for (recursive_directory_iterator i(p); i != end; ++i) {
		file_type type = i->status().type();
		if (!is_directory(i->status()) && !is_regular_file(i->status()) && !is_symlink(i->status())) {
			continue;
		}

		path rel_path(make_path_relative(p, i->path()));
		if (!rel_path.empty())
			f(rel_path, i);
	}
}

