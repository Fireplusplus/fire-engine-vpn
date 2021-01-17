#include <memory.h>
#include <assert.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "dh_group.h"
#include "log.h"

#define DEBUG_OPENSSL_ERROR() do {	\
			char tmp[1024] = {0};	\
			DEBUG("%s", ERR_error_string(ERR_get_error(), tmp));	\
		} while (0)

void openssl_init()
{
#if OPENSSL_API_COMPAT < 0x10100000L
	ERR_load_crypto_strings();
	ERR_free_strings();
#endif

#if OPENSSL_API_COMPAT < 0x10100000L
	SSL_load_error_strings();
#endif
}

void debug_openssl_error()
{
	DEBUG_OPENSSL_ERROR();
}

static BIGNUM * gen_random_data(DH *dh);

struct dh_group_st {
	DH *dh;				/* dh群 */
	BIGNUM *pri_key;	/* dh群私钥 */
	BIGNUM *pub_key;	/* dh群公钥 */
	int key_size;		/* 密钥长度 */
};

struct dh_group_st * dh_create()
{
	struct dh_group_st *group = (struct dh_group_st*)malloc(sizeof(struct dh_group_st));
	if (!group)
		return NULL;
	
	group->dh = DH_new_by_nid(NID_ffdhe2048);
	if (!group->dh) {
		dh_destroy(group);
		return NULL;
	}

	group->pri_key = gen_random_data(group->dh);
	if (!group->pri_key) {
		dh_destroy(group);
		return NULL;
	}

	group->key_size = BN_num_bytes(group->pri_key);
	
	group->pub_key = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	if (!group->pub_key || !ctx) {
		goto failed;
	}

	/* pub = g ^ pri_key % p */
	if (BN_mod_exp(group->pub_key, DH_get0_g(group->dh), group->pri_key, DH_get0_p(group->dh), ctx) != 1)
		goto failed;

	BN_CTX_free(ctx);
	return group;

failed:
	if (ctx)
		BN_CTX_free(ctx);
	
	dh_destroy(group);
	return NULL;
}

void dh_destroy(struct dh_group_st *group)
{
	if (!group)
		return;
	
	if (group->dh)
		DH_free(group->dh);
	
	if (group->pri_key)
		BN_free(group->pri_key);

	if (group->pub_key)
		BN_free(group->pub_key);
	
	free(group);
}

/* 生成随机数 */
static BIGNUM * gen_random_data(DH *dh)
 {
	BIGNUM *rand = BN_new();
	if (!rand)
		return NULL;
	
	if (BN_rand_range(rand, DH_get0_p(dh)) != 1) {
		BN_free(rand);
		return NULL;
	}

	while (BN_is_zero(rand)) {
		BN_rand_range(rand, DH_get0_p(dh));
	}

	return rand;
}

/* 获取密钥长度 */
int dh_keysize(struct dh_group_st *group)
{
	return group ? group->key_size : -1;
}

/* 生成公钥 */
int dh_pubkey(struct dh_group_st *group, uint8_t *pubkey, uint32_t *osize)
{
	if (!group || !pubkey || !osize)
		return -1;
	
	int size = BN_num_bytes(group->pub_key);
	if (size <= 0 || (uint32_t)size > *osize) {
		DEBUG("get pubkey failed: key size: %d, out size: %d", size, *osize);
		return -1;
	}

	*osize = BN_bn2bin(group->pub_key, pubkey);
	assert(*osize == (uint32_t)size);
	return 0;
}

/* 生成共享密钥 */
int dh_sharekey(struct dh_group_st *group, uint8_t *pubkey, uint32_t publen, 
			uint8_t *sharekey, uint32_t *osize)
{
	int size = 0;
	if (!group || !pubkey || !sharekey || !publen || !osize)
		return -1;
	
	BIGNUM *pub = BN_bin2bn(pubkey, publen, NULL);
	if (!pub) {
		DUMP_HEX("invalid pubkey", pubkey, publen);
		return -1;
	}

	BIGNUM *key = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	if (!key || !ctx)
		goto failed;
	
	/* key = shared_num ^ m_pri_key % p */
	if (BN_mod_exp(key, pub, group->pri_key, DH_get0_p(group->dh), ctx) != 1)
		goto failed;
	
	BN_CTX_free(ctx);
	ctx = NULL;

	size = BN_num_bytes(key);
	if (size <= 0 || (uint32_t)size > *osize) {
		DEBUG("get sharekey failed: key size: %d, out size: %d", size, *osize);
		goto failed;
	}

	*osize = BN_bn2bin(key, sharekey);
	assert(*osize == (uint32_t)size);
	return 0;

failed:
	if (key)
		BN_free(key);
	if (ctx)
		BN_CTX_free(ctx);
	
	return -1;
}

void dh_group_example()
{
	openssl_init();

	struct dh_group_st *dh1 = dh_create();
	struct dh_group_st *dh2 = dh_create();

	unsigned char pubkey1[1024];
	unsigned char pubkey2[1024];
	unsigned int sz1 = sizeof(pubkey1), sz2 = sizeof(pubkey2);
	dh_pubkey(dh1, pubkey1, &sz1);
	dh_pubkey(dh2, pubkey2, &sz2);

	unsigned char sharekey1[1024];
	unsigned char sharekey2[1024];
	unsigned int s1 = sizeof(sharekey1), s2 = sizeof(sharekey2);

	dh_sharekey(dh1, pubkey2, sz1, sharekey1, &s1);
	dh_sharekey(dh2, pubkey1, sz1, sharekey2, &s2);
	
	DUMP_HEX("dh1", sharekey1, s1);
	DUMP_HEX("dh2", sharekey2, s2);

	if (memcmp(sharekey1, sharekey2, s1) == 0)
		printf("success\n");
	else
		printf("failed\n");
}
