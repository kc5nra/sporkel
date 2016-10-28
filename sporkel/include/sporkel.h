#pragma once

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
#include <memory>

extern "C" {
#endif

typedef struct sporkel_public_key sporkel_public_key_t;
typedef struct sporkel_secret_key sporkel_secret_key_t;
typedef struct sporkel_keypair sporkel_keypair_t;
typedef struct sporkel_signature sporkel_signature_t;
typedef struct sporkel_tmp_dir sporkel_tmp_dir_t;
typedef struct sporkel_hash sporkel_hash_t;

typedef enum sporkel_log_level {
	SPORKEL_DEBUG,
	SPORKEL_INFO,
	SPORKEL_WARNING,
	SPORKEL_ERROR
} sporkel_log_level_t;


typedef void (*sporkel_log_cb)(void *data, sporkel_log_level_t level, const char *message);
typedef void (*sporkel_progress_cb)(void *data, size_t current, size_t total);
typedef struct sporkel_callback
{
	sporkel_progress_cb progress_cb;
	void *progress_data;
	sporkel_log_cb log_cb;
	void *log_data;
} sporkel_callback_t;

// crypto
sporkel_public_key_t *sporkel_public_key_from_hex(const char *hex, size_t size);
sporkel_secret_key_t *sporkel_secret_key_from_hex(const char *hex, size_t size);
void sporkel_public_key_destroy(sporkel_public_key_t *key);
void sporkel_secret_key_destroy(sporkel_secret_key_t *key);
void sporkel_signature_destroy(sporkel_signature_t *signature);
const char *sporkel_public_key_hex(const sporkel_public_key_t *key);
size_t sporkel_public_key_hex_len();
const char *sporkel_secret_key_hex(const sporkel_secret_key_t *key);
size_t sporkel_secret_key_hex_len();
const char *sporkel_signature_hex(const sporkel_signature_t *signature);
size_t sporkel_signature_hex_len();

// keypair
sporkel_keypair_t *sporkel_keypair_create(void);
void sporkel_keypair_destroy(sporkel_keypair_t *pair);
const sporkel_public_key_t *sporkel_keypair_public_key(const sporkel_keypair_t *pair);
const sporkel_secret_key_t *sporkel_keypair_secret_key(const sporkel_keypair_t *pair);

// signature
sporkel_signature_t *sporkel_signature_from_hex(const char *hex, size_t size);

// sign
sporkel_signature_t *sporkel_sign(const sporkel_secret_key_t *key,
		const unsigned char *data, size_t len);
bool sporkel_verify(const sporkel_public_key_t *key, const sporkel_signature_t *sig,
		const unsigned char *data, size_t len);

// patch
bool sporkel_patch_apply(const char *before_path, const char *patch_path, const char *tmp_path,
		bool keep_tmp_path, sporkel_callback_t *cb);
bool sporkel_patch_create(const char *before_path, const char *after_path, const char *patch_path,
		unsigned num_threads, unsigned memory_limit, const char *cache_path, unsigned lzma_preset,
		bool require_exact_patch_target,
		sporkel_callback_t *cb);

// patch util
sporkel_tmp_dir_t *sporkel_tmp_dir_create(void);
void sporkel_tmp_dir_destroy(sporkel_tmp_dir_t *dir);
const char *sporkel_tmp_dir_path(const sporkel_tmp_dir_t *dir);

// hash
sporkel_hash_t *sporkel_hash_file(const char *path);
void sporkel_hash_destroy(sporkel_hash_t *hash);
const char *sporkel_hash_hex(const sporkel_hash_t *hash);
size_t sporkel_hash_hex_len();

#ifdef __cplusplus
}

namespace sporkel {
	template <typename T>
	struct deleter {
		void operator()(T *o) {(void)o;}
	};
	template <>
	struct deleter<sporkel_public_key_t> {
		void operator()(sporkel_public_key_t *pk) {sporkel_public_key_destroy(pk);}
	};
	template <>
	struct deleter<sporkel_secret_key_t> {
		void operator()(sporkel_secret_key_t *sk) {sporkel_secret_key_destroy(sk);}
	};
	template <>
	struct deleter<sporkel_keypair_t> {
		void operator()(sporkel_keypair_t *kp) {sporkel_keypair_destroy(kp);}
	};
	template <>
	struct deleter<sporkel_signature_t> {
		void operator()(sporkel_signature_t *sig) {sporkel_signature_destroy(sig);}
	};
	template <>
	struct deleter<sporkel_tmp_dir_t> {
		void operator()(sporkel_tmp_dir_t *dir) {sporkel_tmp_dir_destroy(dir);}
	};

	template <typename T>
	using ptr = std::unique_ptr<T, deleter<T>>;

	using public_key_ptr = ptr<sporkel_public_key_t>;
	using secret_key_ptr = ptr<sporkel_secret_key_t>;
	using keypair_ptr    = ptr<sporkel_keypair_t>;
	using signature_ptr  = ptr<sporkel_signature_t>;
	using tmp_dir_ptr    = ptr<sporkel_tmp_dir_t>;
	using hash_ptr       = ptr<sporkel_hash_t>;

	inline const char *sporkel_public_key_hex(const public_key_ptr &ptr)
	{
		return sporkel_public_key_hex(ptr.get());
	}
	inline const char *sporkel_secret_key_hex(const secret_key_ptr &ptr)
	{
		return sporkel_secret_key_hex(ptr.get());
	}
	inline const char *sporkel_signature_hex(const signature_ptr &ptr)
	{
		return sporkel_signature_hex(ptr.get());
	}
	inline const char *sporkel_hash_hex(const hash_ptr &ptr)
	{
		return sporkel_hash_hex(ptr.get());
	}

	inline const sporkel_public_key_t *sporkel_keypair_public_key(const keypair_ptr &pair)
	{
		return sporkel_keypair_public_key(pair.get());
	}
	inline const sporkel_secret_key_t *sporkel_keypair_secret_key(const keypair_ptr &pair)
	{
		return sporkel_keypair_secret_key(pair.get());
	}

	inline sporkel_signature_t *sporkel_sign(const secret_key_ptr &key,
			const unsigned char *data, size_t len)
	{
		return sporkel_sign(key.get(), data, len);
	}
	inline bool sporkel_verify(const public_key_ptr &key, const signature_ptr &sig,
			const unsigned char *data, size_t len)
	{
		return sporkel_verify(key.get(), sig.get(), data, len);
	}

	inline const char *sporkel_tmp_dir_path(const tmp_dir_ptr &dir)
	{
		return sporkel_tmp_dir_path(dir.get());
	}
}
#endif
