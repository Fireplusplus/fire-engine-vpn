#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>

#include <iostream>
#include <unordered_map>

#include "tunnel.h"
#include "log.h"
#include "tun.h"
#include "crypto.h"
#include "local_config.h"
#include "ipc.h"
#include "ev.h"
#include "proto.h"
#include "fd_send.h"

using namespace std;

struct tunnel_st {
	int fd;							/* 加密流通信句柄 */
	int seed;						/* 随机种子 */
	struct crypto_st *crypt;		/* 加密器 */
	char user[MAX_USER_LEN];		/* 用户名 */
	uint64_t last_active;			/* 上次活跃时间 */
};

struct tunnel_manage_st s_tunnel_manage;
static unordered_map<int, tunnel_st*> s_tunnel_list;		/* 隧道信息缓存表 */

/* 自定义event分发函数 */
uint32_t tunnel_ev_rss(int fd, void *arg)
{
	struct tunnel_st *tl = (struct tunnel_st *)arg;
	return tl->seed;
}

void enc_input(int fd, short event, void *arg)
{

}

/* TODO: 添加定时清理 */
static void tunnel_destroy(struct tunnel_st *tl)
{
	ev_unregister(tl->fd);

	unordered_map<int, tunnel_st*>::iterator it= s_tunnel_list.find(tl->fd);
	if (it != s_tunnel_list.end())
		s_tunnel_list.erase(it);
	
	crypto_destroy(tl->crypt);
	
	if (tl->fd)
		close(tl->fd);
	
	INFO("conn(%s) fd(%d) is broken", tl->user, tl->fd);
	free(tl);
}

static tunnel_st * tunnel_create(int fd, uint8_t *buf, int size)
{
	struct cmd_tunnel_st *cmd = (struct cmd_tunnel_st *)buf;
	if (!buf || size != (int)(cmd->klen + sizeof(struct cmd_tunnel_st))) {
		DEBUG("invalid tunnel cmd size: %d, expect: %lu", size, cmd->klen + sizeof(struct cmd_tunnel_st));
		return NULL;
	}

	unordered_map<int, tunnel_st*>::iterator it= s_tunnel_list.find(fd);
	if (it != s_tunnel_list.end()) {
		WARN("fd(%d) is already in use, user(%s) established failed", fd, cmd->user);
		return NULL;
	}

	tunnel_st *tl = (tunnel_st*)calloc(1, sizeof(tunnel_st));
	if (!tl)
		return NULL;
	
	memcpy(tl->user, cmd->user, sizeof(tl->user));
	tl->fd = fd;
	tl->seed = cmd->seed;
	tl->crypt = crypto_create(cmd->pubkey, cmd->klen);
	if (!tl->crypt)
		goto failed;
	
	if (ev_register(fd, enc_input, tl) < 0)
		goto failed;
	
	s_tunnel_list[fd] = tl;
	INFO("conn(%s) fd(%d) established success", tl->user, tl->fd);
	return tl;

failed:
	tunnel_destroy(tl);
	return NULL;
}

void conn_listen()
{
	uint8_t buf[BUF_SIZE];
	int vpn_fd = ipc_fd(s_tunnel_manage.recv);
	int new_fd;
	
	while (1) {
		int size = sizeof(buf) / sizeof(buf[0]);

		if (recv_fd(vpn_fd, &new_fd, buf, &size) < 0) {
			continue;
		}

		(void)tunnel_create(new_fd, buf, size);
	}
}
