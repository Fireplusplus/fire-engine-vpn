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

using namespace std;

struct event_action_st {
	ipc_st * (*create)();
	void (*destroy)(ipc_st *);
	void (*on_do)(int, short, void *);
	const char *desc;
};

static unordered_map<int, ser_cli_node*> s_sc_info_list;		/* 事件缓存表 */
static int s_server;

static void sc_info_add(ipc_st *ipc, ser_cli_node *sc)
{
	assert(ipc && sc);
	
	unordered_map<int, ser_cli_node*>::iterator it = s_sc_info_list.find(ipc_fd(ipc));
	if (it != s_sc_info_list.end()) {
		return;
	}
	
	s_sc_info_list[ipc_fd(ipc)] = sc;
}

static void sc_info_del(ipc_st *ipc)
{
	unordered_map<int, ser_cli_node*>::iterator it = s_sc_info_list.find(ipc_fd(ipc));
	if (it != s_sc_info_list.end()) {
		s_sc_info_list.erase(it);
	}
}

static ser_cli_node * sc_info_create(ipc_st *ipc, int server)
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
	ev_unregister(ipc_fd(sc->ipc));
	crypto_destroy(sc->crypt);
	dh_destroy(sc->dh);
	ipc_destroy(sc->ipc);

	free(sc);
}

static ipc_st * client_create()
{
	return ipc_client_create(AF_INET, get_server_ip(), get_server_port());
}

static ipc_st * listener_create()
{
	return ipc_listener_create(AF_INET, get_server_ip(), get_server_port());
}

static ipc_st * sc_info_ipc(int fd)
{
	unordered_map<int, ser_cli_node*>::iterator it = s_sc_info_list.find(fd);
	if (it == s_sc_info_list.end())
		return NULL;
	
	assert(it->second->ipc);
	return it->second->ipc;
}

/* 读事件回调 */
static void on_read(int fd, short what, void *arg)
{
	ipc_st *ipc = sc_info_ipc(fd);
	
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
	ipc_st *ipc = ipc_accept(sc_info_ipc(listen));
	if (!ipc)
		return;

	ser_cli_node *sc = sc_info_create(ipc, 1);
	if (!sc) {
		WARN("create sc info failed");
		ipc_destroy(ipc);
		return;
	}
	
	if (ev_register(ipc_fd(ipc), on_read, sc) < 0) {
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
	
	ipc_st *ipc = pevs->create();
	if (!ipc) {
		ERROR("%s create failed", pevs->desc);
		goto failed;
	}

	sc = sc_info_create(ipc, s_server);
	if (ev_register(ipc_fd(ipc), pevs->on_do, sc) < 0) {
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
int event_init(int server)
{
	if (server)
		s_server = 1;
	else
		s_server = 0;
	
	if (ev_init() < 0)
		return -1;
	
	event_register();
	return 0;
}
