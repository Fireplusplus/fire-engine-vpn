#include <memory.h>
#include <assert.h>

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

DH * dh_create_ex(int prime_len, int generator, BN_GENCB *cb);

DH * dh_create()
{
	return dh_create_ex(64, DH_GENERATOR_2, NULL);
}

void dh_destroy(DH *dh)
{
	if (dh)
		DH_free(dh);
}

static int check_pubkey(DH *dh)
{
	assert(dh);
	int err = 0;

	if (DH_check_pub_key(dh, DH_get0_pub_key(dh), &err) != 1) {
		if (err & DH_CHECK_PUBKEY_TOO_SMALL)
			DEBUG("DH_check_pub_key: pubkey too small");
		else if (err & DH_CHECK_PUBKEY_TOO_LARGE)
			DEBUG("DH_check_pub_key: pubkey too large");
		else
			DEBUG("DH_check_pub_key: unknown error: %d", err);
		return -1;
	}

	return 0;
}

DH * dh_create_ex(int prime_len, int generator, BN_GENCB *cb)
{
	int err = 0;
	DH *dh = DH_new();
	if (!dh) {
		DEBUG("DH_new failed");
		return NULL;
	}

	if (DH_generate_parameters_ex(dh , prime_len, generator, cb) != 1) {
		DEBUG("DH_generate_parameters_ex failed");
		goto failed;
	}

	if (DH_check(dh, &err) != 1) {
		if (err & DH_CHECK_P_NOT_PRIME)
			DEBUG("DH_check: p value is not prime");
		else if (err & DH_CHECK_P_NOT_SAFE_PRIME)
			DEBUG("DH_check: p value is not a safe prime");
		else if (err & DH_UNABLE_TO_CHECK_GENERATOR)
			DEBUG("DH_check: unable to check the generator value");
		else if (err & DH_NOT_SUITABLE_GENERATOR)
			DEBUG("DH_check: the g value is not a generator");
		else
			DEBUG("DH_check: unknown error: %d", err);
		goto failed;
	}

	if (DH_generate_key(dh) != 1) {
		DEBUG("DH_generate_key failed");
		goto failed;
	}

	if (check_pubkey(dh) < 0)
		goto failed;

	return dh;

failed:
	if (dh)
		DH_free(dh);
	return NULL;
}

int dh_pubkey(DH *dh, unsigned char *pubkey, unsigned int *osize)
{
	if (!dh || !pubkey || !osize)
		return -1;

	const BIGNUM *pub = DH_get0_pub_key(dh);
	if (!pub) {
		return -1;
	}

	int size = BN_num_bytes(pub);
	if (size <= 0 || (unsigned int)size >= *osize) {
		DEBUG("get pubkey failed: key size: %d, out size: %d", size, *osize);
		return -1;
	}

	*osize = BN_bn2bin(pub, pubkey);
	assert(*osize == (unsigned int)size);

	DUMP_HEX("dh_pubkey", pubkey, *osize);
	return 0;
}

int dh_sharekey(DH *dh, unsigned char *pubkey, unsigned int publen, 
			unsigned char *sharekey, unsigned int *osize)
{
	if (!dh || !pubkey || !sharekey || !publen || !osize)
		return -1;
	
	if (*osize < publen) {
		DEBUG("out buf too small: out: %d, expect: %d", *osize, publen);
		return -1;
	}

	DUMP_HEX("dh_sharekey pubkey", pubkey, publen);
	BIGNUM *pub = BN_bin2bn(pubkey, publen, NULL);
	if (!pub) {
		DUMP_HEX("invalid pubkey", pubkey, publen);
		return -1;
	}

	int ret = DH_compute_key(sharekey, pub, dh);
	if (ret <= 0) {
		DEBUG_OPENSSL_ERROR();
		BN_free(pub);
		return -1;
	}
	
	*osize = ret;
	return 0;
}
