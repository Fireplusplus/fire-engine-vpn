#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string.h>

#include "crypto.h"
#include "dh_group.h"
#include "log.h"

struct crypto_st {
	uint8_t key[32];			/**< 密钥 */
	uint32_t key_size;			/**< 密钥长度 */
	EVP_CIPHER_CTX *enc;		/**< 加密器 */
	EVP_CIPHER_CTX *dec;		/**< 解密器 */
};

/** @brief 创建密码管理器
 * @param[in] key 密钥
 * @param[in] size 密钥长度		
 * @return 成功返回初始化的密码管理器，失败返回NULL
 */	
struct crypto_st * crypto_create(const uint8_t *key, uint32_t size)
{
	if (!key || !size)
		return NULL;
	
	struct crypto_st *crypt = (struct crypto_st *)calloc(1, sizeof(struct crypto_st));
	if (!crypt)
		return NULL;
	
	//uint8_t iv[EVP_MAX_IV_LENGTH] = {0};

	crypt->enc = EVP_CIPHER_CTX_new();
	crypt->dec = EVP_CIPHER_CTX_new();
	if (!crypt->enc || !crypt->dec)
		goto failed;
	
	crypt->key_size = MIN(sizeof(crypt->key), size);
	memcpy(crypt->key, key, crypt->key_size);
	
	/*if (EVP_EncryptInit_ex(crypt->enc, EVP_aes_128_ecb(), NULL, crypt->key, iv) != 1 ||
			EVP_DecryptInit_ex(crypt->dec, EVP_aes_128_ecb(), NULL, crypt->key, iv) != 1)
		goto failed;

	DUMP_HEX("iv", iv, sizeof(iv));
	
	if (EVP_CIPHER_CTX_set_key_length(crypt->enc, crypt->key_size) != 1 ||
			EVP_CIPHER_CTX_set_key_length(crypt->dec, crypt->key_size) != 1) {
		DEBUG("key_size: %u", crypt->key_size);
		debug_openssl_error();
		goto failed;
	}*/

	return crypt;

failed:
	crypto_destroy(crypt);
	return NULL;
}

/** @brief 销毁密码管理器
 * @param[in] crypt 密码管理器	
 * @return 无
 */
void crypto_destroy(struct crypto_st *crypt)
{
	if (!crypt)
		return;
	
	if (crypt->enc)
		EVP_CIPHER_CTX_free(crypt->enc);
	
	if (crypt->dec)
		EVP_CIPHER_CTX_free(crypt->dec);
	
	free(crypt);
}

/** @brief 获取加密后数据的长度
 * @param[in] len 数据长度
 * @return 加密后数据长度
 */
int crypto_encrypt_size(uint32_t len)
{
	if (len % AES_BLOCK_SIZE)
		return (len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
	
	return len;
}

/** @brief 加密
 * @param[in] in 待加密数据
 * @param[in] isize 待加密数据长度
 * @param[out] out 输出缓冲区
 * @param[out] osize 输入表示输出缓冲区长度，输出表示加密后长度
 * @return 0：成功 非0：失败
 */
int crypto_encrypt(const struct crypto_st *crypt, const uint8_t *in, uint32_t isize,
					uint8_t *out, uint32_t *osize)
{
	if (!crypt || !in || !isize || !out || !osize)
		return -1;
	
	int enc_len = 0, final_len = 0;
	uint8_t iv[EVP_MAX_IV_LENGTH] = {0};

	if (EVP_EncryptInit_ex(crypt->enc, EVP_aes_128_ecb(), NULL, crypt->key, iv) != 1)
		goto failed;
	
	if (EVP_CIPHER_CTX_set_key_length(crypt->enc, crypt->key_size) != 1) {
		DEBUG("key_size: %u", crypt->key_size);
		goto failed;
	}
	
	if (EVP_EncryptUpdate(crypt->enc, out, &enc_len, in, isize) != 1 ||
			enc_len < 0) {
		goto failed;
	}
	
	if ((uint32_t)enc_len < isize &&
			EVP_EncryptFinal_ex(crypt->enc, out + enc_len, &final_len) != 1) {
		goto failed;
	}
	
	*osize = enc_len + final_len;
	return 0;

failed:
	debug_openssl_error();
	EVP_CIPHER_CTX_cleanup(crypt->enc);
	return -1;
}

/** @brief 解密
 * @param[inout] data 输入表示待解密数据，输出表示解密后数据
 * @param[inout] isize 输入表示待加密数据长度，输出表示解密后数据长度
 * @return 0：成功 非0：失败
 */
int crypto_decrypt(const struct crypto_st *crypt, uint8_t *data, uint32_t *size)
{
	if (!crypt || !data || !size)
		return -1;
	
	int dec_len = 0, final_len = 0;
	uint8_t iv[EVP_MAX_IV_LENGTH] = {0};

	if (EVP_DecryptInit_ex(crypt->dec, EVP_aes_128_ecb(), NULL, crypt->key, iv) != 1) {
		goto failed;
	}
	
	if (EVP_CIPHER_CTX_set_key_length(crypt->dec, crypt->key_size) != 1) {
		DEBUG("key_size: %u", crypt->key_size);
		goto failed;
	}
	
	if (EVP_DecryptUpdate(crypt->dec, data, &dec_len, data, *size) != 1 ||
			dec_len < 0) {
		goto failed;
	}
	
	if (EVP_DecryptFinal_ex(crypt->dec, data + dec_len, &final_len) != 1) {
		goto failed;
	}
	
	*size = dec_len + final_len;
	return 0;

failed:
	EVP_CIPHER_CTX_cleanup(crypt->dec);
	return -1;
}

static void crypto_enc_dec_call(struct crypto_st *crypt)
{
	char src[] = "abcdefghijklmnopqrstuvwxy";
	char enc[1024] = {0};
	uint32_t enc_size = sizeof(enc);

	DUMP_HEX("src", src, strlen(src));

	if(crypto_encrypt(crypt, (uint8_t*)src, strlen(src), (uint8_t*)enc, &enc_size) < 0) {
		ERROR("encrypt failed: src len: %u, enc_size: %u", (uint32_t)strlen(src), enc_size);
		return;
	}

	DUMP_HEX("enc", enc, enc_size);

	if (crypto_decrypt(crypt, (uint8_t*)enc, &enc_size) < 0) {
		ERROR("decrypt failed: enc_size: %u", enc_size);
		return;
	}

	DUMP_HEX("dec", enc, enc_size);

	if (strlen(src) != enc_size || memcmp(src, enc, strlen(src)) != 0)
		DEBUG("crypto test failed: src len: %u, old_enc: %u", (uint32_t)strlen(src), enc_size);
	else
		DEBUG("crypto test success");
	
	DEBUG("crypto_encrypt_size: %d\n", crypto_encrypt_size(strlen(src)));
}

/** @brief 生成随机数
 * @return 0：失败 非0：随机数
 */
int safe_rand()
{
	BIGNUM *rand = BN_new();
	if (!rand)
		return 0;

	int num;
	if (BN_rand(rand, sizeof(num) * 8, 0, 0) != 1)
		return 0;
	
	if (BN_bn2bin(rand, (unsigned char*)&num) != sizeof(num))
		return 0;
	
	return num;
}

void crypto_example()
{
	char key[16] = "123456789012345";

	DUMP_HEX("key", key, sizeof(key));
	openssl_init();

	struct crypto_st *crypt = crypto_create((uint8_t*)key, sizeof(key));
	INFO("first call");
	crypto_enc_dec_call(crypt);
	INFO("second call");
	crypto_enc_dec_call(crypt);
	crypto_destroy(crypt);

	INFO("rand call");
	for (int i = 0; i < 10; i++) {
		INFO("rand_%d: %d", i, safe_rand());
	}
}

