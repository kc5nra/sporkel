project(sodium)

add_definitions(
	-DSODIUM_STATIC
	-DSODIUM_EXPORT=
	-D_CONSOLE
	/wd4244)

include_directories(
	libsodium_override/
	libsodium_override/sodium
	libsodium/src/libsodium/include
	libsodium/src/libsodium/include/sodium)

set(sodium_HEADERS
	libsodium/src/libsodium/include/sodium.h
	libsodium/src/libsodium/include/sodium/core.h
	libsodium/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h
	libsodium/src/libsodium/include/sodium/crypto_auth.h
	libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha256.h
	libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha512.h
	libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha512256.h
	libsodium/src/libsodium/include/sodium/crypto_box.h
	libsodium/src/libsodium/include/sodium/crypto_box_curve25519xsalsa20poly1305.h
	libsodium/src/libsodium/include/sodium/crypto_core_hsalsa20.h
	libsodium/src/libsodium/include/sodium/crypto_core_salsa20.h
	libsodium/src/libsodium/include/sodium/crypto_core_salsa2012.h
	libsodium/src/libsodium/include/sodium/crypto_core_salsa208.h
	libsodium/src/libsodium/include/sodium/crypto_generichash.h
	libsodium/src/libsodium/include/sodium/crypto_generichash_blake2b.h
	libsodium/src/libsodium/include/sodium/crypto_hash.h
	libsodium/src/libsodium/include/sodium/crypto_hash_sha256.h
	libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h
	libsodium/src/libsodium/include/sodium/crypto_int32.h
	libsodium/src/libsodium/include/sodium/crypto_int64.h
	libsodium/src/libsodium/include/sodium/crypto_onetimeauth.h
	libsodium/src/libsodium/include/sodium/crypto_onetimeauth_poly1305.h
	libsodium/src/libsodium/include/sodium/crypto_pwhash_scryptsalsa208sha256.h
	libsodium/src/libsodium/include/sodium/crypto_scalarmult.h
	libsodium/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h
	libsodium/src/libsodium/include/sodium/crypto_secretbox.h
	libsodium/src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h
	libsodium/src/libsodium/include/sodium/crypto_shorthash.h
	libsodium/src/libsodium/include/sodium/crypto_shorthash_siphash24.h
	libsodium/src/libsodium/include/sodium/crypto_sign.h
	libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h
	libsodium/src/libsodium/include/sodium/crypto_sign_edwards25519sha512batch.h
	libsodium/src/libsodium/include/sodium/crypto_stream.h
	libsodium/src/libsodium/include/sodium/crypto_stream_aes128ctr.h
	libsodium/src/libsodium/include/sodium/crypto_stream_chacha20.h
	libsodium/src/libsodium/include/sodium/crypto_stream_salsa20.h
	libsodium/src/libsodium/include/sodium/crypto_stream_salsa2012.h
	libsodium/src/libsodium/include/sodium/crypto_stream_salsa208.h
	libsodium/src/libsodium/include/sodium/crypto_stream_xsalsa20.h
	libsodium/src/libsodium/include/sodium/crypto_uint16.h
	libsodium/src/libsodium/include/sodium/crypto_uint32.h
	libsodium/src/libsodium/include/sodium/crypto_uint64.h
	libsodium/src/libsodium/include/sodium/crypto_uint8.h
	libsodium/src/libsodium/include/sodium/crypto_verify_16.h
	libsodium/src/libsodium/include/sodium/crypto_verify_32.h
	libsodium/src/libsodium/include/sodium/crypto_verify_64.h
	libsodium/src/libsodium/include/sodium/export.h
	libsodium/src/libsodium/include/sodium/randombytes.h
	libsodium/src/libsodium/include/sodium/randombytes_salsa20_random.h
	libsodium/src/libsodium/include/sodium/randombytes_sysrandom.h
	libsodium/src/libsodium/include/sodium/utils.h
	libsodium/src/libsodium/include/sodium/version.h)

set(sodium_SOURCES
	libsodium/src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c
	libsodium/src/libsodium/crypto_auth/crypto_auth.c
	libsodium/src/libsodium/crypto_auth/hmacsha256/auth_hmacsha256_api.c
	libsodium/src/libsodium/crypto_auth/hmacsha256/cp/hmac_hmacsha256.c
	libsodium/src/libsodium/crypto_auth/hmacsha256/cp/verify_hmacsha256.c
	libsodium/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512_api.c
	libsodium/src/libsodium/crypto_auth/hmacsha512/cp/hmac_hmacsha512.c
	libsodium/src/libsodium/crypto_auth/hmacsha512/cp/verify_hmacsha512.c
	libsodium/src/libsodium/crypto_auth/hmacsha512256/auth_hmacsha512256_api.c
	libsodium/src/libsodium/crypto_auth/hmacsha512256/cp/hmac_hmacsha512256.c
	libsodium/src/libsodium/crypto_auth/hmacsha512256/cp/verify_hmacsha512256.c
	libsodium/src/libsodium/crypto_box/crypto_box.c
	libsodium/src/libsodium/crypto_box/crypto_box_easy.c
	libsodium/src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305_api.c
	libsodium/src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/after_curve25519xsalsa20poly1305.c
	libsodium/src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/before_curve25519xsalsa20poly1305.c
	libsodium/src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/box_curve25519xsalsa20poly1305.c
	libsodium/src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/keypair_curve25519xsalsa20poly1305.c
	libsodium/src/libsodium/crypto_core/hsalsa20/core_hsalsa20_api.c
	libsodium/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20.c
	libsodium/src/libsodium/crypto_core/salsa2012/core_salsa2012_api.c
	libsodium/src/libsodium/crypto_core/salsa2012/ref/core_salsa2012.c
	libsodium/src/libsodium/crypto_core/salsa208/core_salsa208_api.c
	libsodium/src/libsodium/crypto_core/salsa208/ref/core_salsa208.c
	libsodium/src/libsodium/crypto_core/salsa20/core_salsa20_api.c
	libsodium/src/libsodium/crypto_core/salsa20/ref/core_salsa20.c
	libsodium/src/libsodium/crypto_generichash/blake2/generichash_blake2_api.c
	libsodium/src/libsodium/crypto_generichash/blake2/ref/blake2b-ref.c
	libsodium/src/libsodium/crypto_generichash/blake2/ref/generichash_blake2b.c
	libsodium/src/libsodium/crypto_generichash/crypto_generichash.c
	libsodium/src/libsodium/crypto_hash/crypto_hash.c
	libsodium/src/libsodium/crypto_hash/sha256/hash_sha256_api.c
	libsodium/src/libsodium/crypto_hash/sha256/cp/hash_sha256.c
	libsodium/src/libsodium/crypto_hash/sha512/hash_sha512_api.c
	libsodium/src/libsodium/crypto_hash/sha512/cp/hash_sha512.c
	libsodium/src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c
	libsodium/src/libsodium/crypto_onetimeauth/poly1305/donna/auth_poly1305_donna.c
	libsodium/src/libsodium/crypto_onetimeauth/poly1305/donna/verify_poly1305_donna.c
	libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
	libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305_api.c
	libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305_try.c
	libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c
	libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c
	libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c
	libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c
	libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c
	libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/sse/pwhash_scryptsalsa208sha256_sse.c
	libsodium/src/libsodium/crypto_scalarmult/crypto_scalarmult.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/donna_c64/base_curve25519_donna_c64.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/donna_c64/smult_curve25519_donna_c64.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/base_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_0_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_1_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_add_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_copy_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_cswap_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_frombytes_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_invert_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_mul121666_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_mul_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_sq_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_sub_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_tobytes_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/scalarmult_curve25519_ref10.c
	libsodium/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519_api.c
	libsodium/src/libsodium/crypto_secretbox/crypto_secretbox.c
	libsodium/src/libsodium/crypto_secretbox/crypto_secretbox_easy.c
	libsodium/src/libsodium/crypto_secretbox/xsalsa20poly1305/ref/box_xsalsa20poly1305.c
	libsodium/src/libsodium/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305_api.c
	libsodium/src/libsodium/crypto_shorthash/crypto_shorthash.c
	libsodium/src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphash24.c
	libsodium/src/libsodium/crypto_shorthash/siphash24/shorthash_siphash24_api.c
	libsodium/src/libsodium/crypto_sign/crypto_sign.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_0.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_1.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_add.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_cmov.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_copy.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_frombytes.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_invert.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_isnegative.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_isnonzero.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_mul.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_neg.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_pow22523.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_sq.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_sq2.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_sub.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_tobytes.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_add.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_double_scalarmult.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_frombytes.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_madd.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_msub.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p1p1_to_p2.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p1p1_to_p3.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p2_0.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p2_dbl.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_0.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_dbl.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_tobytes.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_to_cached.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_to_p2.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_precomp_0.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_scalarmult_base.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_sub.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_tobytes.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/keypair.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/open.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/sc_muladd.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/sc_reduce.c
	libsodium/src/libsodium/crypto_sign/ed25519/ref10/sign.c
	libsodium/src/libsodium/crypto_sign/ed25519/sign_ed25519_api.c
	libsodium/src/libsodium/crypto_sign/edwards25519sha512batch/ref/fe25519_edwards25519sha512batch.c
	libsodium/src/libsodium/crypto_sign/edwards25519sha512batch/ref/ge25519_edwards25519sha512batch.c
	libsodium/src/libsodium/crypto_sign/edwards25519sha512batch/ref/sc25519_edwards25519sha512batch.c
	libsodium/src/libsodium/crypto_sign/edwards25519sha512batch/ref/sign_edwards25519sha512batch.c
	libsodium/src/libsodium/crypto_sign/edwards25519sha512batch/sign_edwards25519sha512batch_api.c
	libsodium/src/libsodium/crypto_stream/aes128ctr/portable/afternm_aes128ctr.c
	libsodium/src/libsodium/crypto_stream/aes128ctr/portable/beforenm_aes128ctr.c
	libsodium/src/libsodium/crypto_stream/aes128ctr/portable/common_aes128ctr.c
	libsodium/src/libsodium/crypto_stream/aes128ctr/portable/consts_aes128ctr.c
	libsodium/src/libsodium/crypto_stream/aes128ctr/portable/int128_aes128ctr.c
	libsodium/src/libsodium/crypto_stream/aes128ctr/portable/stream_aes128ctr.c
	libsodium/src/libsodium/crypto_stream/aes128ctr/portable/xor_afternm_aes128ctr.c
	libsodium/src/libsodium/crypto_stream/aes128ctr/stream_aes128ctr_api.c
	libsodium/src/libsodium/crypto_stream/chacha20/ref/stream_chacha20_ref.c
	libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20_api.c
	libsodium/src/libsodium/crypto_stream/crypto_stream.c
	libsodium/src/libsodium/crypto_stream/salsa2012/ref/stream_salsa2012.c
	libsodium/src/libsodium/crypto_stream/salsa2012/ref/xor_salsa2012.c
	libsodium/src/libsodium/crypto_stream/salsa2012/stream_salsa2012_api.c
	libsodium/src/libsodium/crypto_stream/salsa208/ref/stream_salsa208.c
	libsodium/src/libsodium/crypto_stream/salsa208/ref/xor_salsa208.c
	libsodium/src/libsodium/crypto_stream/salsa208/stream_salsa208_api.c
	libsodium/src/libsodium/crypto_stream/salsa20/ref/stream_salsa20_ref.c
	libsodium/src/libsodium/crypto_stream/salsa20/ref/xor_salsa20_ref.c
	libsodium/src/libsodium/crypto_stream/salsa20/stream_salsa20_api.c
	libsodium/src/libsodium/crypto_stream/xsalsa20/ref/stream_xsalsa20.c
	libsodium/src/libsodium/crypto_stream/xsalsa20/ref/xor_xsalsa20.c
	libsodium/src/libsodium/crypto_stream/xsalsa20/stream_xsalsa20_api.c
	libsodium/src/libsodium/crypto_verify/16/ref/verify_16.c
	libsodium/src/libsodium/crypto_verify/16/verify_16_api.c
	libsodium/src/libsodium/crypto_verify/32/ref/verify_32.c
	libsodium/src/libsodium/crypto_verify/32/verify_32_api.c
	libsodium/src/libsodium/crypto_verify/64/ref/verify_64.c
	libsodium/src/libsodium/crypto_verify/64/verify_64_api.c
	libsodium/src/libsodium/randombytes/randombytes.c
	libsodium/src/libsodium/randombytes/salsa20/randombytes_salsa20_random.c
	libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c
	libsodium/src/libsodium/sodium/core.c
	libsodium/src/libsodium/sodium/runtime.c
	libsodium/src/libsodium/sodium/utils.c
	libsodium/src/libsodium/sodium/version.c)

SET_SOURCE_FILES_PROPERTIES(${sodium_SOURCES} PROPERTIES LANGUAGE CXX)

add_library(sodium
	${sodium_SOURCES}
	${sodium_HEADERS})

set(SODIUM_INCLUDE_DIRS 
	"${CMAKE_CURRENT_SOURCE_DIR}/libsodium_override"
	"${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/libsodium/include"
	"${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/libsodium/include/sodium" 
		CACHE PATH "sodium include paths")
mark_as_advanced(SODIUM_INCLUDE_DIRS)
