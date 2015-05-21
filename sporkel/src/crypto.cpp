#include "common.h"
#include <algorithm>

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