#ifndef __EVENT_20201213__
#define __EVENT_20201213__

#include "ipc.h"
#include "proto.h"

enum negotiate_status {
	SC_INIT,
	SC_KEY_C_SEND,
	SC_KEY_R_SEND,
	SC_AUTH_C_SEND,
	SC_AUTH_R_SEND,
	SC_SUCCESS,
	SC_LISTEN,
};

struct ser_cli_node {
	uint8_t 				server;			/* 是否服务端 */
	uint8_t 				status;			/* 协商状态, 协商成功的需要移除 */
	uint32_t 				seed;			/* 随机种子 */
	uint64_t 				last_active_time;	/* 上次活跃时间 */

	ipc_st 					*ipc;			/* 通信句柄 */
	struct event 			*ev;			/* event, 这里的暂时应该没用到 TODO: 移除 */
	struct dh_group_st 		*dh;			/* dh群 */
	struct crypto_st 		*crypt;			/* 加密器 */
	const struct user_st 	*user;			/* 用户信息 */
};

extern ipc_st *s_tunnel_ipc;

/* 初始化服务环境 */
int event_init(int server);

/* 创建套接字并注册事件 */
void event_register();

const char * sc_status2str(uint8_t status);

#endif
