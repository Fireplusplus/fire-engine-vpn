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

static BIGNUM * gen_random_data(DH *dh);

struct dh_group_st {
	DH *dh;				/* dh群 */
	BIGNUM *pri_key;	/* dh群私钥 */
	BIGNUM *pub_key;	/* dh群公钥 */
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
