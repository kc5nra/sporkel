#include "../include/sporkel.h"

#include "common.h"

#include <sodium.h>

struct sporkel_keypair {
	sporkel_public_key_t pub;
	sporkel_secret_key_t sec;
};

sporkel_keypair_t *sporkel_keypair_create(void)
{
	sodium_init();

	std::unique_ptr<sporkel_keypair_t> pair;
	try {
		pair.reset(new sporkel_keypair_t());
	} catch (const std::bad_alloc&) {
		return nullptr;
	}

	crypto_sign_keypair(pair->pub.bin, pair->sec.bin);

	bin2hex(pair->pub.bin, pair->pub.hex);
	bin2hex(pair->sec.bin, pair->sec.hex);

	return pair.release();
}

void sporkel_keypair_destroy(sporkel_keypair_t *pair)
{
	delete pair;
}

const sporkel_public_key_t *sporkel_keypair_public_key(const sporkel_keypair_t *pair)
{
	return &pair->pub;
}

const sporkel_secret_key_t *sporkel_keypair_secret_key(const sporkel_keypair_t *pair)
{
	return &pair->sec;
}
