#pragma once

#include "../include/sporkel.h"

#include <sodium.h>

#include <cstring>
#include <memory>
#include <new>

#define SPORKEL_SECRETKEY_SIZE (crypto_sign_SECRETKEYBYTES * 2U)
#define SPORKEL_PUBLICKEY_SIZE (crypto_sign_PUBLICKEYBYTES * 2U)
#define SPORKEL_SIGNATURE_SIZE (crypto_sign_BYTES * 2U)

namespace sporkel_detail {
	template <typename T>
	struct crypto_size {};
	template <>
	struct crypto_size<sporkel_public_key_t> {
		static const size_t bin_bytes = crypto_sign_PUBLICKEYBYTES;
		static const size_t hex_bytes = SPORKEL_PUBLICKEY_SIZE;
	};
	template <>
	struct crypto_size<sporkel_secret_key_t> {
		static const size_t bin_bytes = crypto_sign_SECRETKEYBYTES;
		static const size_t hex_bytes = SPORKEL_SECRETKEY_SIZE;
	};
	template <>
	struct crypto_size<sporkel_signature_t> {
		static const size_t bin_bytes = crypto_sign_BYTES;
		static const size_t hex_bytes = SPORKEL_SIGNATURE_SIZE;
	};
}

struct sporkel_public_key {
	unsigned char bin[crypto_sign_PUBLICKEYBYTES];
	char          hex[SPORKEL_PUBLICKEY_SIZE + 1] = {0};
};

struct sporkel_secret_key {
	unsigned char bin[crypto_sign_SECRETKEYBYTES];
	char          hex[SPORKEL_SECRETKEY_SIZE + 1] = {0};
};

struct sporkel_signature {
	unsigned char bin[crypto_sign_BYTES];
	char          hex[SPORKEL_SIGNATURE_SIZE + 1] = {0};
};

template <typename T1, size_t N1, typename T2, size_t N2>
void bin2hex(T1(&bin)[N1], T2(&hex)[N2])
{
	static_assert((N1 * 2 + 1) <= N2, "hex buffer too small");
	sodium_bin2hex(hex, N1 * 2 + 1, bin, N1);
}

template <typename T1, size_t N1, typename T2, size_t N2>
void hex2bin(T1(&hex)[N1], T2(&bin)[N2])
{
	static_assert(N2 >= (N1 / 2), "bin buffer too small");
	sodium_hex2bin(bin, N2, hex, N2 * 2, NULL, NULL, NULL);
}
