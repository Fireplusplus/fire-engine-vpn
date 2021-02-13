#ifndef __CRYPTO_20201227__
#define __CRYPTO_20201227__

/** @brief 创建密码管理器
 * @param[in] key 密钥
 * @param[in] size 密钥长度		
 * @return 成功返回初始化的密码管理器，失败返回NULL
 */
struct crypto_st * crypto_create(const uint8_t *key, uint32_t size);

/** @brief 销毁密码管理器
 * @param[in] crypt 密码管理器	
 * @return 无
 */
void crypto_destroy(struct crypto_st *crypt);

/** @brief 获取加密后数据的长度
 * @param[in] len 数据长度
 * @return 加密后数据长度
 */
int crypto_encrypt_size(uint32_t len);

/** @brief 获取密钥
 * @param[in] crypt 加密器
 * @param[out] buf 输出缓冲
 * @param[in] size 输出缓冲长度 
 * @return 成功: 密钥成都, 失败: <0
 */
int crypto_key(const struct crypto_st *crypt, uint8_t *buf, uint32_t size);

/** @brief 加密
 * @param[in] in 待加密数据
 * @param[in] isize 待加密数据长度
 * @param[out] out 输出缓冲区
 * @param[out] osize 输入表示输出缓冲区长度，输出表示加密后长度
 * @return 0：成功 非0：失败
 */
int crypto_encrypt(const struct crypto_st *crypt, const uint8_t *in, uint32_t isize,
					uint8_t *out, uint32_t *osize);

/** @brief 解密
 * @param[inout] data 输入表示待解密数据，输出表示解密后数据
 * @param[inout] isize 输入表示待加密数据长度，输出表示解密后数据长度
 * @return 0：成功 非0：失败
 */
int crypto_decrypt(const struct crypto_st *crypt, uint8_t *data, uint32_t *size);

/** @brief 生成随机数
 * @return 0：失败 非0：随机数
 */
int safe_rand();

void crypto_example();

#endif