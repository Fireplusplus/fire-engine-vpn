#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <event2/event.h>

#include <iostream>
#include <string>
#include <unordered_map>

using namespace std;

struct event_action_st {
	int (*create)();
	void (*destroy)(int);
	void (*on_do)(int, short, void *);
};

struct cli_info_st {
	struct event *ev;
};

static unordered_map<int, cli_info_st*> s_ev_list;	/* client信息缓存 */
static int s_server;								/* 是否服务端 */
static event_action_st s_events_hd[2];				/* 事件处理函数集,0: client, 1: server */

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
		return -1;
	}
	
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		return -1;
	}
	
	return 0;
}

static int listener_create()
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("create_listener socket\n");
		return -1;
	}
	
	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_port = htons(6666);
	inet_pton(AF_INET, "127.0.0.1", &local.sin_addr.s_addr);
	
	int flag = 1, len = sizeof(int);
	if( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, len) == -1)
		goto failed;
	
	if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
		perror("create_listener bind\n");
		goto failed;
	}
	
	if (listen(sock, 10) < 0)
		goto failed;

	set_unblock(sock);
	
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
		perror("read_cb read");
		return;
	}
	
	if (len == 0) {
		printf("read null\n");
		
		if (s_server) {
			cli_list_remove(fd);
		} else {
			event_base_loopbreak((struct event_base*)arg);
		}
		return;
	}
	
	buf[len] = '\0';
	printf("recv: %s, len: %d, what: %d\n", buf, len, what);
}

static void on_listen(int listen, short what, void *arg)
{
	struct sockaddr_in peer;
	socklen_t len = sizeof(peer);
	int sock = accept4(listen, (struct sockaddr*)&peer, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (sock < 0) {
		perror("accept4");
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
	
	printf("accept a client: sock(%d)\n", sock);
}

static int client_create()
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("client_create socket\n");
		return -1;
	}
	
	struct sockaddr_in peer;
	peer.sin_family = AF_INET;
	peer.sin_port = htons(6666);
	inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr.s_addr);
	
	if (connect(sock, (struct sockaddr*)&peer, sizeof(peer)) < 0) {
		perror("client_create connect");
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

void event_run()
{
	static event_action_st *hd = &s_events_hd[s_server];
	struct event* ev = NULL;
	int sock = 0;
	
	struct event_base *base = event_base_new();
	if (!base) {
		printf("client_run event_base_new failed\n");
		goto failed;
	}
	
	sock = hd->create();
	if (sock < 0)
		goto failed;

	ev = event_new(base, sock, EV_READ | EV_PERSIST, hd->on_do, base);
	event_add(ev, NULL);
	
	event_base_dispatch(base);
	
failed:
	if (ev)
		event_free(ev);
	hd->destroy(sock);
	
	if (base)
		event_base_free(base);
}

int event_init(int server)
{
	if (server)
		s_server = 1;
	else
		s_server = 0;
	
	struct event_action_st cli_ev = {client_create, client_destroy, on_read};
	struct event_action_st ser_ev = {listener_create, listener_destroy, on_listen};
	s_events_hd[0] = cli_ev;
	s_events_hd[1] = ser_ev;
	
	return 0;
}

