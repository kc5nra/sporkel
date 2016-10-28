#include "common.h"
#include <algorithm>

#include <boost/filesystem.hpp>

#include "../../util/util.hpp"

template <typename T>
static inline T *from_hex(const char *hex, size_t size)
{
	if (size < sporkel_detail::crypto_size<T>::hex_bytes)
		return nullptr;

	std::unique_ptr<T> crypto;
	try {
		crypto.reset(new T());
	} catch (const std::bad_alloc&) {
		return nullptr;
	}

	std::copy_n(hex, sporkel_detail::crypto_size<T>::hex_bytes,
			crypto->hex);
	hex2bin(crypto->hex, crypto->bin);

	return crypto.release();
}

sporkel_public_key_t *sporkel_public_key_from_hex(const char *hex, size_t size)
{
	return from_hex<sporkel_public_key_t>(hex, size);
}

sporkel_secret_key_t *sporkel_secret_key_from_hex(const char *hex, size_t size)
{
	return from_hex<sporkel_secret_key_t>(hex, size);
}

sporkel_signature_t *sporkel_signature_from_hex(const char *hex, size_t size)
{
	return from_hex<sporkel_signature_t>(hex, size);
}

void sporkel_public_key_destroy(sporkel_public_key_t *key)
{
	delete key;
}

void sporkel_secret_key_destroy(sporkel_secret_key_t *key)
{
	delete key;
}

void sporkel_signature_destroy(sporkel_signature_t *signature)
{
	delete signature;
}

const char *sporkel_public_key_hex(const sporkel_public_key_t *key)
{
	return key->hex;
}

size_t sporkel_public_key_hex_len()
{
	return sporkel_detail::crypto_size<sporkel_public_key_t>::hex_bytes;
}

const char *sporkel_secret_key_hex(const sporkel_secret_key_t *key)
{
	return key->hex;
}

size_t sporkel_secret_key_hex_len()
{
	return sporkel_detail::crypto_size<sporkel_secret_key_t>::hex_bytes;
}

const char *sporkel_signature_hex(const sporkel_signature_t *signature)
{
	return signature->hex;
}

size_t sporkel_signature_hex_len()
{
	return sporkel_detail::crypto_size<sporkel_signature_t>::hex_bytes;
}


sporkel_hash_t *sporkel_hash_file(const char *path)
{
	if (!path)
		return nullptr;

	std::unique_ptr<sporkel_hash_t> hash;
	std::vector<unsigned char> data;
	try {
		auto size = boost::filesystem::file_size(path);
		sporkel_util::get_file_contents(path, size, data);

		hash.reset(new sporkel_hash_t{});
	} catch (...) {
		return nullptr;
	}

	if (crypto_generichash(hash->bin, sporkel_detail::crypto_size<sporkel_hash_t>::bin_bytes, data.data(), data.size(), nullptr, 0))
		return nullptr;

	bin2hex(hash->bin, hash->hex);
	return hash.release();
}

void sporkel_hash_destroy(sporkel_hash_t *hash)
{
	delete hash;
}

const char *sporkel_hash_hex(const sporkel_hash_t *hash)
{
	return hash->hex;
}

size_t sporkel_hash_hex_len()
{
	return sporkel_detail::crypto_size<sporkel_hash_t>::hex_bytes;
}