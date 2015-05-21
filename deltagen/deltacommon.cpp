#include <sodium.h>
#include <fstream>

#include "deltacommon.h"

void hash_delta_info(const std::string &p, const delta_info &di, crypto_generichash_state &state)
{
	crypto_generichash_update(&state, (const unsigned char *) p.c_str(), p.length());
	crypto_generichash_update(&state, (const unsigned char *) &di.type, sizeof(decltype(di.type)));
	crypto_generichash_update(&state, (const unsigned char *) &di.size, sizeof(decltype(di.size)));
	crypto_generichash_update(&state, di.hash, sizeof(di.hash));
}

void hash_entry(const directory_entry &i, crypto_generichash_state &state)
{
	
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
		path sym_path(::read_symlink(p));
		std::string s = sym_path.generic_string();
		crypto_generichash_update(&state, (unsigned char *) s.c_str(), s.length());
		return;
	}

	if (is_directory(i.status())) {
		crypto_generichash_update(&state, (const unsigned char *)"d", 1);
		return;
	}
}

void hash_entry(const directory_entry &i, unsigned char (&hash)[crypto_generichash_BYTES])
{
	crypto_generichash_state state;

	crypto_generichash_init(&state, NULL, 0, sizeof(hash));
	hash_entry(i, state);
	crypto_generichash_final(&state, hash, sizeof(hash));
}

path get_temp_directory() {
	
	path p(unique_path());
	return temp_directory_path() / p;
}

void hex2bin(const std::string &hex, std::vector<unsigned char> &bin)
{
    bin.resize(hex.length() / 2 + 1);
    const char *end;
    size_t size;
    sodium_hex2bin(bin.data(), bin.size(), hex.c_str(), hex.length(), NULL, &size, &end);
    // assert hex.length() == size?
}
