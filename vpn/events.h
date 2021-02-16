#ifndef __EVENT_20201213__
#define __EVENT_20201213__

#include "ipc.h"

struct ser_cli_node {
	ipc_st *ipc;					/* 通信句柄 */
	int seed;						/* 随机种子 */
	struct event *ev;				/* event, 这里的暂时应该没用到 TODO: 移除 */
	struct dh_group_st *dh;			/* dh群 */
	struct crypto_st *crypt;		/* 加密器 */
	int status;						/* TODO: 协商状态 */
	uint64_t last_active;			/* TODO: 上次活跃时间, 超时需要移除 */

	char user[MAX_USER_LEN];		/* 用户名 */
	
	uint8_t server:1;
};


/* 初始化服务环境 */
int event_init(int server);

#endif
