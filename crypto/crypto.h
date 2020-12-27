#ifndef __CRYPTO_20201227__
#define __CRYPTO_20201227__

struct crypto_st * crypto_create(const uint8_t *key, uint32_t size);

void crypto_destroy(struct crypto_st *crypt);

/* 获取加密后数据长度 */
int crypto_encrypt_size(uint32_t len);

/* 加密 */
int crypto_encrypt(const struct crypto_st *crypt, const uint8_t *in, uint32_t isize,
					uint8_t *out, uint32_t *osize);

/* 解密 */
int crypto_decrypt(const struct crypto_st *crypt, uint8_t *data, uint32_t *size);

void crypto_example();

#endif