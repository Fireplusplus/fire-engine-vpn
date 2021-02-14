#ifndef __EVENT_20201213__
#define __EVENT_20201213__

#include "ipc.h"

struct ser_cli_node {
	ipc_st *ipc;
	int seed;
	struct event *ev;
	struct dh_group_st *dh;
	struct crypto_st *crypt;
	
	uint8_t server:1;
};


/* 初始化服务环境 */
int event_init(int server);

#endif
