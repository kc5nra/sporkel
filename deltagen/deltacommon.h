#pragma once

#include <functional>
#include <boost/filesystem.hpp>
#include <string>
#include <sodium.h>

using namespace boost::filesystem;

struct delta_info {
	std::string hash;
	file_type type;
	unsigned long long size;
	bool deleted;
};

enum delta_op_type {
	DELETE,
	ADD,
	PATCH
};

struct delta_op {
	enum delta_op_type type;
	std::string path;

	delta_op() {}
	delta_op(enum delta_op_type type, const std::string &path) : type(type), path(path) {}
	
	template<class Archive>
	void serialize(Archive & archive)
	{
		archive(type, path); // serialize things by passing them to the archive
	}
};

struct delta_op_toc {
	std::vector<struct delta_op> ops;

	template<class Archive>
	void serialize(Archive & archive)
	{
		archive(ops); // serialize things by passing them to the archive
	}
};


void process_tree(path &p, std::function<void(path &p, recursive_directory_iterator &i)> f);
bool delta_info_equals(struct delta_info &l, struct delta_info& r);

void hash_delta_info(const std::string &path, struct delta_info &di, crypto_generichash_state &state);
std::string hash_entry(recursive_directory_iterator &i);
void hash_entry(recursive_directory_iterator &i, crypto_generichash_state &state);

path make_path_relative(path &a_From, path &a_To);

path get_temp_directory();
