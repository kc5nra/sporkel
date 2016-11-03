#include "../include/sporkel.h"

#include "common.h"

#include <sodium.h>
#include <algorithm>
#include <cstring>

sporkel_signature_t *sporkel_sign(const sporkel_secret_key_t *key,
		const unsigned char *data, size_t len)
{
	std::unique_ptr<sporkel_signature_t> sig;
	try {
		sig.reset(new sporkel_signature_t());
	} catch (const std::bad_alloc&) {
		return nullptr;
	}

	sodium_init();

	crypto_sign_detached(sig->bin, nullptr, data, len, key->bin);
	bin2hex(sig->bin, sig->hex);

	return sig.release();
}

bool sporkel_verify(const sporkel_public_key_t *key,
		const sporkel_signature_t *sig,
		const unsigned char *data, size_t len)
{
	sodium_init();

	return crypto_sign_verify_detached(sig->bin, data, len, key->bin) == 0;
}
