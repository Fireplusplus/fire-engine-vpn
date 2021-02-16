#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>

#include <iostream>
#include <unordered_map>

#include "log.h"
#include "tun.h"
#include "mem.h"
#include "events.h"
#include "crypto.h"
#include "dh_group.h"
#include "local_config.h"
#include "simple_proto.h"
#include "ipc.h"
#include "ev.h"
#include "proto.h"

using namespace std;

struct tunnel_st {
	int fd;
	int seed;
	struct crypto_st *crypt;
};

extern struct tunnel_manage_st s_tunnel_manage;
static unordered_map<int, tunnel_st*> s_tunnel_list;		/* 隧道信息缓存表 */


static uint32_t tunnel_ev_rss(int fd, void *arg)
{
	struct tunnel_st *tl = (struct tunnel_st *)arg;
	return tl->seed;
}

void enc_input(int fd, short event, void *arg)
{

}

void tunnel_destroy(struct tunnel_st *tl)
{
	crypto_destroy(tl->crypt);
}

static tunnel_st * tunnel_create(struct cmd_tunnel_st *cmd)
{
	tunnel_st *tl = (tunnel_st*)calloc(1, sizeof(tunnel_st));
	if (!tl)
		return NULL;
	
	tl->seed = cmd->seed;
	tl->crypt = crypto_create(cmd->pubkey, cmd->klen);
	if (!tl->crypt)
		goto failed;
	
		if (ev_register(tl->fd, enc_input, tl) < 0)
	
	return tl;

failed:
	tunnel_destroy(tl);
	return NULL;
}

static void tunnel_list_add(int fd, tunnel_st *tunnel)
{
	assert(tunnel);
	
	unordered_map<int, tunnel_st*>::iterator it = s_tunnel_list.find(fd);
	if (it != s_tunnel_list.end()) {
		return;
	}
	
	s_sc_info_list[ipc] = sc;
}

static void sc_info_del(int ipc)
{
	unordered_map<int, ser_cli_node*>::iterator it = s_sc_info_list.find(ipc);
	if (it != s_sc_info_list.end()) {
		s_sc_info_list.erase(it);
	}
}

static ser_cli_node * sc_info_create(int ipc, int server)
{
	ser_cli_node *sc = (ser_cli_node *)alloc_die(sizeof(ser_cli_node));
	
	sc->ipc = ipc;
	sc->server = server;

	sc_info_add(ipc, sc);
	return sc;
}

static void sc_info_destroy(ser_cli_node *sc)
{
	if (!sc)
		return;
	
	sc_info_del(sc->ipc);
	ev_unregister(sc->ipc);
	crypto_destroy(sc->crypt);
	dh_destroy(sc->dh);
	ipc_destroy(sc->ipc);

	free(sc);
}

static int client_create()
{
	int ipc = ipc_client_create(AF_INET, get_server_ip(), get_server_port());
	if (ipc < 0) {
		return -1;
	}

	return ipc;
}

static int listener_create()
{
	int ipc = ipc_listener_create(AF_INET, get_server_ip(), get_server_port());
	if (ipc < 0) {
		return -1;
	}

	return ipc;
}

/* 读事件回调 */
static void on_read(int ipc, short what, void *arg)
{
    char buf[65535];
	int len = ipc_recv(ipc, buf, sizeof(buf));
	if (len < 0) {
		return;
	}
	
	if (len == 0) {
		sc_info_destroy((ser_cli_node *)arg);
		return;
	}
	
	DEBUG("recv: len: %d, what: %d\n", len, what);
	if (on_cmd((ser_cli_node *)arg, (uint8_t *)&buf, len) < 0) {
		DEBUG("on cmd failed");
		sc_info_destroy((ser_cli_node *)arg);
	}
}

/* 服务端监听回调 */
static void on_listen(int listen, short what, void *arg)
{
	int ipc = ipc_accept(AF_INET, listen);
	if (ipc < 0)
		return;

	ser_cli_node *sc = sc_info_create(ipc, 1);
	if (!sc) {
		WARN("create sc info failed");
		ipc_destroy(ipc);
		return;
	}
	
	if (ev_register(ipc, on_read, sc) < 0) {
		sc_info_destroy(sc);
		return;
	}
}

/* 创建套接字并注册事件 */
static void event_register()
{
	struct ser_cli_node *sc;
	struct event_action_st ser_evs = {
			listener_create, ipc_destroy, on_listen, "listtener",	/* 服务端监听 */
		};
	struct event_action_st cli_evs = {
			client_create, ipc_destroy, on_read, "client",			/* 客户端监听 */
		};
	
	struct event_action_st *pevs = s_server ? &ser_evs : &cli_evs;
	
	int ipc = pevs->create();
	if (!ipc) {
		ERROR("%s create failed", pevs->desc);
		goto failed;
	}

	sc = s_server ? NULL : sc_info_create(ipc, 0);
	if (ev_register(ipc, pevs->on_do, sc) < 0) {
		ERROR("%s register failed", pevs->desc);
		goto failed;
	}

	INFO("%s register success", pevs->desc);
		
	if (!s_server && start_connect(sc) < 0) {	/* 客户端发起主动协商 */
		goto failed;
	}

	return;

failed:
	//destroy
	exit(-1);
}

/* 初始化服务环境 */
int event_init()
{
	if (ev_init(3, tunnel_ev_rss) < 0)
		return -1;

	return 0;
}
