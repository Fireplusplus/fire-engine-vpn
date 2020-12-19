#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <event2/event.h>

#include <iostream>
#include <string>
#include <unordered_map>

#include "log.h"
#include "tun.h"
#include "local_config.h"

using namespace std;

struct event_action_st {
	int (*create)();
	void (*destroy)(int);
	void (*on_do)(int, short, void *);
	const char *desc;
};

struct cli_info_st {
	struct event *ev;
};

static unordered_map<int, cli_info_st*> s_ev_list;	/* client信息缓存 */
struct event_base *s_ev_base;
static int s_server;								/* 是否服务端 */

cli_info_st * cli_info_create()
{
	return (cli_info_st *)calloc(1, sizeof(cli_info_st));
}

void cli_info_destroy(cli_info_st *cli)
{
	if (!cli)
		return;
	
	if (cli->ev) {
		event_free(cli->ev);
	}
	free(cli);
}

void cli_list_save(int fd, cli_info_st *cli)
{
	assert(cli);
	
	unordered_map<int, cli_info_st*>::iterator it = s_ev_list.find(fd);
	if (it != s_ev_list.end()) {
		cli_info_destroy(it->second);
	}
	
	s_ev_list[fd] = cli;
}

void cli_list_remove(int fd)
{
	unordered_map<int, cli_info_st*>::iterator it = s_ev_list.find(fd);
	if (it != s_ev_list.end()) {
		cli_info_destroy(it->second);
		s_ev_list.erase(it);
	}
}

int set_unblock(int fd)
{
	int flags;
	if ((flags = fcntl(fd, F_GETFL, NULL)) < 0) {
		DEBUG("fcntl failed: %s", strerror(errno));
		return -1;
	}
	
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		DEBUG("fcntl failed: %s", strerror(errno));
		return -1;
	}
	
	return 0;
}

static int listener_create()
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		ERROR("socket error: %s", strerror(errno));
		return -1;
	}
	
	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_port = htons(get_server_port());
	inet_pton(AF_INET, get_server_ip(), &local.sin_addr.s_addr);
	
	int flag = 1, len = sizeof(int);
	if( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, len) == -1) {
		DEBUG("reuseaddr failed: %s", strerror(errno));
	}
	
	int i;
	for (i = 1; i < 4; i++) {
		if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
			local.sin_port = htons(get_server_port() + i);
			DEBUG("try bind next port: %d", get_server_port() + i);
		} else {
			break;
		}
	}
	if (i == 4) {
		ERROR("bind error: %s", strerror(errno));
		goto failed;
	}
	
	if (listen(sock, 10) < 0) {
		ERROR("listen error: %s", strerror(errno));
		goto failed;
	}

	(void)set_unblock(sock);
	return sock;

failed:
	close(sock);
	return -1;
}

static void listener_destroy(int sock)
{
	if (sock < 0)
		return;

	close(sock);
}

static void on_read(int fd, short what, void *arg)
{
    char buf[10240];
    int len = read(fd, buf, sizeof(buf) - 1);
	if (len < 0) {
		WARN("read failed: %s", strerror(errno));
		return;
	}
	
	if (len == 0) {
		INFO("read end\n");
		
		if (s_server) {
			cli_list_remove(fd);
		} else {
			//TODO：free fd
			event_base_loopbreak((struct event_base*)arg);
		}
		return;
	}
	
	buf[len] = '\0';
	INFO("recv: %s, len: %d, what: %d\n", buf, len, what);
}

static void on_listen(int listen, short what, void *arg)
{
	struct sockaddr_in peer;
	socklen_t len = sizeof(peer);
	int sock = accept4(listen, (struct sockaddr*)&peer, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (sock < 0) {
		WARN("accept error: %s", strerror(errno));
		return;
	}
	
	struct event* ev = event_new((struct event_base*)arg, sock, EV_READ | EV_ET, on_read, NULL);
	event_add(ev, NULL);
	
	cli_info_st *cli = cli_info_create();
	if (!cli) {
		return;
	}
	
	cli->ev = ev;
	cli_list_save(sock, cli);
	
	INFO("accept a client: sock(%d)\n", sock);
}

static int client_create()
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		WARN("socket failed: %s", strerror(errno));
		return -1;
	}
	
	struct sockaddr_in peer;
	peer.sin_family = AF_INET;
	peer.sin_port = htons(6666);
	inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr.s_addr);
	
	if (connect(sock, (struct sockaddr*)&peer, sizeof(peer)) < 0) {
		WARN("connect failed: %s", strerror(errno));
		goto failed;
	}
	
	set_unblock(sock);
	
	return sock;

failed:
	close(sock);
	return -1;
}

static void client_destroy(int sock)
{
	if (sock < 0)
		return;

	close(sock);
}

/* 注册新事件 */
int event_register(int fd, void (*on_do)(int, short, void *), void *user_data)
{
	if (fd < 0 || !on_do) {
		DEBUG("event_register failed: invalid param: fd: %d, on_do: %p", fd, on_do);
		return -1;
	}

	struct event* ev = event_new(s_ev_base, fd, EV_READ | EV_PERSIST, on_do, user_data ?: s_ev_base);
	if (!ev) {
		DEBUG("event_register failed: invalid param: event create failed");
		return -1;
	}
	
	event_add(ev, NULL);
	INFO("event_register success: fd: %d", fd);
	return 0;
}

static void server_register()
{
	struct event_action_st evs[] = {
		{listener_create, listener_destroy, on_listen, "listtener"},	/* 服务端监听 */
		//{tun_init, tun_finit, on_read, "raw input"}						/* 原始输入 */
	};
	
	for (int i = 0; i < (int)(sizeof(evs) / sizeof(evs[0])); i++) {
		int fd = evs[i].create();
		if (!fd) {
			ERROR("%s creat failed", evs[i].desc);
			goto failed;
		}

		if (event_register(fd, evs[i].on_do, NULL) < 0) {
			ERROR("%s register failed", evs[i].desc);
			goto failed;
		}
	}

	return;

failed:
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
	
	server_register();
	return 0;
}
