#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <iostream>
#include <unordered_map>
#include <unordered_set>

#include "log.h"
#include "mem.h"
#include "events.h"
#include "crypto.h"
#include "dh_group.h"
#include "config.h"
#include "local_config.h"
#include "simple_proto.h"
#include "ipc.h"
#include "ev.h"

using namespace std;

#define SC_NODE_TIMEOUT		10
#define SC_TIMER_INTERVAL	5

struct event_action_st {
	ipc_st * (*create)();
	void (*destroy)(ipc_st *);
	void (*on_do)(int, short, void *);
	const char *desc;
};

ipc_st *s_tunnel_ipc;													/* 与tunnel manage通信的句柄 */
static unordered_map<int, ser_cli_node*> s_sc_info_list;				/* 事件缓存表 */
static int s_server;

static const char * s_sc_status2str[] = {
											"SC_INIT",
											"SC_KEY_C_SEND",
											"SC_KEY_R_SEND",
											"SC_AUTH_C_SEND",
											"SC_AUTH_R_SEND",
											"SC_SUCCESS",
											"SC_LISTEN"
										};

const char * sc_status2str(uint8_t status)
{
	return s_sc_status2str[status];
}

static void sc_info_add(ipc_st *ipc, ser_cli_node *sc)
{
	assert(ipc && sc);
	int fd = ipc_fd(ipc);
	unordered_map<int, ser_cli_node*>::iterator it = s_sc_info_list.find(fd);
	if (it != s_sc_info_list.end()) {
		return;
	}
	
	s_sc_info_list[fd] = sc;
}

static ser_cli_node * sc_info_create(ipc_st *ipc, int server)
{
	ser_cli_node *sc = (ser_cli_node *)alloc_die(sizeof(ser_cli_node));
	
	sc->ipc = ipc;
	sc->server = server;
	sc->last_active_time = cur_time();

	sc_info_add(ipc, sc);
	return sc;
}

static void sc_info_destroy(ser_cli_node *sc)
{
	if (!sc)
		return;

	ev_unregister(ipc_fd(sc->ipc));
	crypto_destroy(sc->crypt);
	dh_destroy(sc->dh);
	ipc_destroy(sc->ipc);

	free(sc);
}

static ipc_st * client_create()
{
	return ipc_client_create(AF_INET, NULL, 0, get_server_ip(), get_server_port());
}

static ipc_st * listener_create()
{
	return ipc_listener_create(AF_INET, get_server_ip(), get_server_port());
}

#if 0
static ipc_st * sc_info_ipc(int fd)
{
	unordered_map<int, ser_cli_node*>::iterator it = s_sc_info_list.find(fd);
	if (it == s_sc_info_list.end())
		return NULL;
	
	assert(it->second->ipc);
	return it->second->ipc;
}
#endif

/* 协商读事件回调 */
static void on_read(int fd, short what, void *arg)
{
	ser_cli_node *sc = (ser_cli_node *)arg;
	char buf[65535];
	int ret;

	ret = pkt_recv(fd, sc->crypt, (uint8_t*)buf, sizeof(buf));
	if (ret < 0) {
		return;
	}

	if (!ret) {
		sc->status = SC_INIT;
		return;
	}

	if (sc->status == SC_SUCCESS)
		return;

	sc->last_active_time = cur_time();
	if (on_cmd((ser_cli_node *)arg, (uint8_t *)&buf) < 0) {
		WARN("on cmd failed, negotiation failed");
	}
}

/* tunnel manage读事件回调 */
static void on_read_manage(int fd, short what, void *arg)
{
	char buf[65535];
	int ret;

	ret = pkt_recv(fd, NULL, (uint8_t*)buf, sizeof(buf));
	if (ret < 0) {
		return;
	}

	if (!ret) {
		WARN("tunnel manage closed, exit !");
		exit(-1);
	}

	struct vpn_head_st *hdr = (struct vpn_head_st *)buf;
	if (hdr->type != PKT_CONN_INFO) {
		return;
	}

	struct cmd_conn_info_st *info = (struct cmd_conn_info_st *)hdr->data;
	if (info->alive_cnt * sizeof(uint32_t) > hdr->old_len) {
		DEBUG("invalid alive_cnt: %d, size: %d", info->alive_cnt, hdr->old_len);
		return;
	}

	unordered_set<uint32_t> seeds_list;
	uint32_t *seeds = (uint32_t *)info->data;
	for (int i = 0; i < info->alive_cnt; i++) {
		seeds_list.insert(seeds[i]);
	}

	for (auto it = s_sc_info_list.begin(); it != s_sc_info_list.end(); ++it) {
		if (it->second->status != SC_SUCCESS)
			continue;

		auto sit = seeds_list.find(it->second->seed);

		if (sit == seeds_list.end()) {
			it->second->status = SC_INIT;
			WARN("reset sc status to SC_INIT: seed: %u", it->second->seed);
		} else {
			INFO("sc is alive: seed: %u", it->second->seed);
		}
	}
}

/* 服务端监听回调 */
static void on_listen(int listen, short what, void *arg)
{
	struct ser_cli_node *s_sc = (struct ser_cli_node *)arg;
	ipc_st *ipc = ipc_accept(s_sc->ipc);
	if (!ipc)
		return;

	ser_cli_node *sc = sc_info_create(ipc, 1);
	if (!sc) {
		WARN("create sc info failed");
		ipc_destroy(ipc);
		return;
	}
	
	if (ev_register(ipc_fd(ipc), on_read, sc) < 0) {
		return;
	}
}

/* 创建套接字并注册事件 */
void event_register()
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
	if (s_server)
		sc->status = SC_LISTEN;

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
	exit(-1);
}

static int reset_tunnel_handle_block(int server)
{
	const char *addr = get_tunnel_addr(server);

	if (s_tunnel_ipc)
		return 0;

	do {
		s_tunnel_ipc = ipc_client_create(AF_UNIX, NULL, 0, addr, 0);
		sleep(1);
	} while (!s_tunnel_ipc);

	if (ev_register(ipc_fd(s_tunnel_ipc), on_read_manage, NULL) < 0) {
		ERROR("s_tunnel_ipc register failed");
		return -1;
	}

	return 0;
}


static void sc_on_timer(void *arg)
{
	uint64_t now = cur_time();
	struct ser_cli_node *sc;
	uint8_t status, reconn = 0, erase = 0;
	
	for (auto it = s_sc_info_list.begin(); it != s_sc_info_list.end();) {
		sc = it->second;
		status = sc->status;

		switch (status) {
		case SC_LISTEN:
			break;
		case SC_SUCCESS:
			break;
		case SC_INIT:
			if (now > it->second->last_active_time + SC_NODE_TIMEOUT) {
				DEBUG("destroy timeout sc: %s, status: %s", 
					get_user_name(it->second->user), sc_status2str(it->second->status));

				sc_info_destroy(it->second);
				it = s_sc_info_list.erase(it);

				if (!s_server)
					reconn = 1;

				erase = 1;
			}
			break;
		default:
			if (now > it->second->last_active_time + SC_NODE_TIMEOUT) {
				DEBUG("destroy timeout sc: %s, status: %s", 
					get_user_name(it->second->user), sc_status2str(it->second->status));
				sc_info_destroy(it->second);
				it = s_sc_info_list.erase(it);
				erase = 1;
			}
			break;
		};

		if (!erase)
			++it;
	}

	if (reconn)
		event_register();

	ev_timer(SC_TIMER_INTERVAL, sc_on_timer, NULL);
}

/* 初始化服务环境 */
int event_init(int server)
{
	if (server)
		s_server = 1;
	else
		s_server = 0;
	
	if (ev_init(0, NULL) < 0)
		return -1;
	
	if (reset_tunnel_handle_block(s_server) < 0)
		return -1;
	
	if (ev_timer(SC_TIMER_INTERVAL << 2, sc_on_timer, NULL) < 0)
		return -1;

	return 0;
}
