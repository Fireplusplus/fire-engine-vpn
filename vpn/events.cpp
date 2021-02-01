#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <event2/event.h>

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

using namespace std;

struct event_action_st {
	int (*create)();
	void (*destroy)(int);
	void (*on_do)(int, short, void *);
	const char *desc;
};

static unordered_map<int, ser_cli_node*> s_sc_info_list;		/* 事件缓存表 */
struct event_base *s_ev_base;
static int s_server;

struct event * event_create(int ipc, event_callback_fn fn, void *arg)
{
	if (ipc < 0 || !fn)
		return NULL;
	
	struct event *ev = event_new(s_ev_base, ipc, EV_READ | EV_PERSIST, fn, arg);
	if (!ev) {
		DEBUG("create event failed");
		return NULL;
	}

	event_add(ev, NULL);
	return ev;
}

void event_destroy(struct event *ev)
{
	if (ev) {
		event_del(ev);
		event_free(ev);
	}
}

ser_cli_node * sc_info_create()
{
	return (ser_cli_node *)alloc_die(sizeof(ser_cli_node));
}

void sc_info_destroy(ser_cli_node *sc)
{
	if (!sc)
		return;
	
	event_destroy(sc->ev);
	crypto_destroy(sc->crypt);
	dh_destroy(sc->dh);
	ipc_destroy(sc->ipc);

	free(sc);
}

void sc_info_add(int ipc, ser_cli_node *sc)
{
	assert(sc);
	
	unordered_map<int, ser_cli_node*>::iterator it = s_sc_info_list.find(ipc);
	if (it != s_sc_info_list.end()) {
		sc_info_destroy(it->second);
	}
	
	s_sc_info_list[ipc] = sc;
}

void sc_info_del(int ipc)
{
	unordered_map<int, ser_cli_node*>::iterator it = s_sc_info_list.find(ipc);
	if (it != s_sc_info_list.end()) {
		sc_info_destroy(it->second);
		s_sc_info_list.erase(it);
	}
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
		sc_info_del(ipc);
		return;
	}
	
	DEBUG("recv: len: %d, what: %d\n", len, what);
	if (on_cmd((ser_cli_node *)arg, (uint8_t *)&buf, len) < 0) {
		DEBUG("on cmd failed");
		sc_info_del(ipc);
	}
}

/* 服务端监听回调 */
static void on_listen(int listen, short what, void *arg)
{
	int ipc = ipc_accept(AF_INET, listen);
	if (ipc < 0)
		return;

	ser_cli_node *sc = sc_info_create();
	if (!sc) {
		WARN("create sc info failed");
		ipc_destroy(ipc);
		return;
	}

	sc->ipc = ipc;
	sc->server = 1;
	
	sc->ev = event_create(ipc, on_read, sc);
	if (!sc->ev) {
		sc_info_destroy(sc);
		return;
	}

	sc_info_add(ipc, sc);
}

/* 注册新事件 */
int event_register(int ipc, void (*on_do)(int, short, void *), void *user_data, int server)
{
	if (ipc < 0 || !on_do) {
		DEBUG("invalid param: ipc: %d, on_do: %p", ipc, on_do);
		return -1;
	}

	struct ser_cli_node *sc = sc_info_create();
	if (!sc) {
		WARN("create sc info failed");
		return -1;
	}

	sc->ipc = ipc;
	sc->server = server;

	sc->ev = event_create(ipc, on_do, sc);
	if (!sc->ev) {
		sc_info_destroy(sc);
		return -1;
	}
	
	sc_info_add(ipc, sc);

	if (!server && start_connect(sc) < 0) {	/* 客户端发起主动协商 */
		sc_info_del(ipc);
		return -1;
	}
	
	return 0;
}

/* 创建服务端套接字并注册事件 */
static void server_register()
{
	struct event_action_st evs[] = {
		{listener_create, ipc_destroy, on_listen, "listtener"},	/* 服务端监听 */
		//{tun_init, tun_finit, on_read, "raw input"},					/* 原始输入 */
	};
	
	for (int i = 0; i < (int)(sizeof(evs) / sizeof(evs[0])); i++) {
		int ipc = evs[i].create();
		if (!ipc) {
			ERROR("%s create failed", evs[i].desc);
			goto failed;
		}

		if (event_register(ipc, evs[i].on_do, NULL, 1) < 0) {
			ERROR("%s register failed", evs[i].desc);
			goto failed;
		}

		INFO("%s register success", evs[i].desc);
	}

	return;

failed:
	//destroy
	exit(-1);
}

/* 创建客户端套接字并注册事件 */
static void client_register()
{
	int ipc = ipc_client_create(AF_INET, get_server_ip(), get_server_port());
	if (ipc < 0) {
		return;
	}

	if (event_register(ipc, on_read, NULL, 0) < 0) {
		goto failed;
	}

	return;

failed:
	ipc_destroy(ipc);
	exit(-1);
}

/* 服务启动运行：循环事件 */
void event_run()
{
	event_base_dispatch(s_ev_base);
}

/* 初始化服务环境 */
int event_init(int server)
{
	if (server)
		s_server = 1;
	else
		s_server = 0;
	
	s_ev_base = event_base_new();
	if (!s_ev_base) {
		ERROR("event_init event_base_new failed\n");
		return -1;
	}
	
	if (s_server)
		server_register();
	else
		client_register();

	return 0;
}
