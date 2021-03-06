#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "log.h"
#include "ev.h"
#include "events.h"
#include "dh_group.h"
#include "crypto.h"
#include "simple_proto.h"
#include "ipc.h"
#include "comm.h"
#include "local_config.h"
#include "config.h"

void usage()
{
	const char *help[] = {
		"  -s                    run in server mode",
		"  -c  [server-ip]       run in client mode, connect to server-ip",
		"  -t                    test the module",
		"      [group]             test dh group module",
		"      [crypto]            test encrypt/decrypt module",
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

void test(const char *opt)
{
	INFO("test: %s", opt);
	
	if (strncmp(opt, "group", strlen("group")) == 0)
		dh_group_example();
	else if (strncmp(opt, "crypto", strlen("crypto")) == 0)
		crypto_example();
	else {
		INFO("unknow test !");
	}

	exit(0);
}

int main(int argc, char *argv[])
{
	if (argc <= 1)
		usage();
	
	signal(SIGPIPE, SIG_IGN);
	
	int server = 0;
	
	int opt;
	do {
		opt = getopt(argc, argv, "sc:t:");
		if (opt < 0)
			break;

		switch (opt) {
		case 's':
			server = 1;
			break;
		case 'c':
			server = 0;
			set_server_ip(optarg);
			break;
		case 't':
			test(optarg);
			break;
		case 'h':
			usage();
			break;
		default:
			break;
		};
	} while (opt);
	
	if (server && config_init() < 0)
		return -1;

	if (event_init(server) < 0) {
		return -1;
	}

	event_register();

	while (1) {
		(void)ev_run();

		sleep(3);
	}

	return 0;
}

