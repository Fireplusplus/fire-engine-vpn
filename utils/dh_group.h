#ifndef __DH_GROUP_20201220__
#define __DH_GROUP_20201220__

#include "dh_group.h"

void openssl_init();
void debug_openssl_error();

struct dh_group_st * dh_create();

void dh_destroy(struct dh_group_st *group);

/* 获取密钥长度 */
int dh_keysize(struct dh_group_st *group);

/* 获取dh群公钥 */
int dh_pubkey(struct dh_group_st *group, uint8_t *pubkey, uint32_t *osize);

/* 获取dh群共享密钥 */
int dh_sharekey(struct dh_group_st *group, uint8_t *pubkey, uint32_t publen, 
			uint8_t *sharekey, uint32_t *osize);

void dh_group_example();

#endif