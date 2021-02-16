#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "ev.h"
#include "events.h"
#include "ipc.h"
#include "tun.h"
#include "proto.h"
#include "local_config.h"

/*
                    t1
                  /
tunnel —— ring_buf —— t2
                  \
                    t3
*/

struct tunnel_manage_st s_tunnel_manage;

//直接将tcp描述符发过来，加入event

void usage()
{
	const char *help[] = {
		"  -s                    run in server mode",
		"  -c                    run in client mode",
		"  -h                    show help",
		NULL
	};

	printf("Usage: fire-vpn [opt] param\n");

	int i = 0;
	while (help[i]) {
		printf("\n%s", help[i++]);
	};

	printf("\n");
	exit(0);
}

static int tunnel_init()
{
	struct sockaddr_in local;

	ipc_st *listen = ipc_listener_create(AF_UNIX, TUNNEL_ADDR, 0);
	if (!listen)
		return -1;
	
	do {
		s_tunnel_manage.recv = ipc_accept(listen);
		sleep(3);
	} while (!s_tunnel_manage.recv);
	
	ipc_destroy(listen);


	s_tunnel_manage.raw_fd = tun_init();
	if (s_tunnel_manage.raw_fd < 0) {
		goto failed;
	}

	return 0;

failed:
	exit(1);
	return -1;
}

static int conn_setup(struct cmd_tunnel_st *tunnel)
{
	if (s_tunnel_manage.server) {

	} else {
		if (ev_register(int ipc, event_callback_fn fn, void *arg) < 0)
	}
}

static void conn_listen()
{
	uint8_t buf[BUF_SIZE];
	int size;
	
	size = ipc_recv(s_tunnel_manage.recv, buf, sizeof(buf));
	if (size <= 0) {
		return;
	}

	if (conn_setup((struct cmd_tunnel_st *)buf) < 0) {
		return;
	}
}

int main(int argc, char *argv[])
{
	if (argc <= 1)
		usage();
	
	int server = 0;
	int opt = getopt(argc, argv, "sct:");
	switch (opt) {
		case 's':
			server = 1;
			break;
		case 'c':
			server = 0;
			break;
		case 'h':
			usage();
			break;
		default:
			usage();
			break;
	};

	if (ev_init() < 0)
		return -1;

	if (tunnel_init() < 0)
		return -1;
	
	INFO("event_run over !\n");

	return 0;
}

