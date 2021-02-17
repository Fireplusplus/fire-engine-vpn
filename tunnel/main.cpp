#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "ev.h"
#include "ipc.h"
#include "tun.h"
#include "proto.h"
#include "local_config.h"
#include "tunnel.h"

/*
                    thread1
                  /
tunnel —— ring_buf —— thread2
                  \
                    thread3
*/



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


int main(int argc, char *argv[])
{
	if (argc <= 1)
		usage();
	
	int opt = getopt(argc, argv, "sc");
	switch (opt) {
		case 's':
			s_tunnel_manage.server = 1;
			break;
		case 'c':
			s_tunnel_manage.server = 0;
			break;
		case 'h':
			usage();
			break;
		default:
			usage();
			break;
	};

	if (ev_init(3, tunnel_ev_rss) < 0)
		return -1;

	if (tunnel_init() < 0)
		return -1;
	
	conn_listen();
	
	INFO("tunnel manage run over !\n");
	return 0;
}

