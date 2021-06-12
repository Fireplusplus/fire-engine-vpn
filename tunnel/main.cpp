#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "log.h"
#include "ev.h"
#include "ipc.h"
#include "tun.h"
#include "proto.h"
#include "local_config.h"
#include "tunnel.h"


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

int main(int argc, char *argv[])
{
	if (argc <= 1)
		usage();
	
	signal(SIGPIPE, SIG_IGN);

	int server;
	int opt = getopt(argc, argv, "sc");
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

	if (ev_init(EV_THREADS_NUM, tunnel_ev_rss) < 0)
		return -1;

	if (tunnel_init(server, EV_THREADS_NUM) < 0)
		return -1;
	
	conn_listen();
	
	INFO("tunnel manage run over !\n");
	return 0;
}

