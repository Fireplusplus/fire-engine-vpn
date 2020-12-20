#ifndef __DH_GROUP_20201220__
#define __DH_GROUP_20201220__

#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "dh_group.h"

void openssl_init();

DH * dh_create();

void dh_destroy(DH *dh);

int dh_pubkey(DH *dh, unsigned char *pubkey, unsigned int *osize);

int dh_sharekey(DH *dh, unsigned char *pubkey, unsigned int len, 
			unsigned char *sharekey, unsigned int *osize);

#endif