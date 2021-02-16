#ifndef __EVENT_TUNNEL_20210214__
#define __EVENT_TUNNEL_20210214__

struct tunnel_manage_st {
	int server;			/* 是否服务端 */
	int raw_fd;			/* 原始输入句柄 */
	int enc_fd;			/* 加密流句柄 */
	ipc_st *recv;		/* 同vpn_manage的通信句柄 */
};

#endif