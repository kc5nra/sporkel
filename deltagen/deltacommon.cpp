#include <sodium.h>
#include <fstream>

#include "base64.h"
#include "deltacommon.h"

path& path_append(path &_this, path::iterator begin, path::iterator end)
{
	for (; begin != end; ++begin)
		_this /= *begin;
	return _this;
}

path make_path_relative(path a_From, path a_To)
{
	a_From = absolute(a_From); a_To = absolute(a_To);
	path ret;
	path::const_iterator itrFrom(a_From.begin()), itrTo(a_To.begin());
	for (path::const_iterator toEnd(a_To.end()), fromEnd(a_From.end()); 
		itrFrom != fromEnd && itrTo != toEnd && *itrFrom == *itrTo; 
		++itrFrom, ++itrTo);

	for (path::const_iterator fromEnd(a_From.end()); itrFrom != fromEnd; ++itrFrom)
	{
		if ((*itrFrom) != ".")
			ret /= "..";
	}

	return path_append(ret, itrTo, a_To.end());
}

void process_tree(path &p, std::function<void(path &path, recursive_directory_iterator &i)> f)
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

void hash_delta_info(std::string &p, struct delta_info &di, crypto_generichash_state &state)
{
	crypto_generichash_update(&state, (const unsigned char *) p.c_str(), strlen(p.c_str()));
	crypto_generichash_update(&state, (const unsigned char *) &di.type, sizeof(decltype(di.type)));
	crypto_generichash_update(&state, (const unsigned char *) &di.size, sizeof(decltype(di.size)));
	crypto_generichash_update(&state, (const unsigned char *) di.hash.c_str(), strlen(di.hash.c_str()));
}

void hash_entry(recursive_directory_iterator &i, crypto_generichash_state &state)
{
	
	auto &path = i->path();
	size_t size = 0;
	if (is_regular_file(i->status()))
		size = (size_t)file_size(i->path());

	if (is_regular(i->status()) || is_symlink(i->status())) {

		char chunk_buffer[16 * 1024];
		size_t chunk_buffer_size = sizeof(chunk_buffer);
		size_t chunk_cnt = size / chunk_buffer_size;
		size_t last_chunk_size = size % chunk_buffer_size;

		std::ifstream file(path.native(), std::ifstream::binary);

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

	if (is_directory(i->status())) {
		crypto_generichash_update(&state, (const unsigned char *)"d", 1);
	}
}

std::string hash_entry(recursive_directory_iterator &i)
{
	crypto_generichash_state state;
	unsigned char hash[crypto_generichash_BYTES];
	
	crypto_generichash_init(&state, NULL, 0, sizeof(hash));
	hash_entry(i, state);
	crypto_generichash_final(&state, hash, sizeof(hash));

	return std::string(base64_encode(&hash[0], sizeof(hash)));
}

path get_temp_directory() {
	
	path p(unique_path());
	return temp_directory_path() / p;
}