#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "events.h"
#include "dh_group.h"
#include "crypto.h"
#include "simple_proto.h"
#include "ipc.h"


void usage()
{
	const char *help[] = {
		"  -s                    run in server mode",
		"  -c                    run in client mode",
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
	
	int server = 0;
	int opt = getopt(argc, argv, "sct:");
	switch (opt) {
		case 's':
			server = 1;
			break;
		case 'c':
			server = 0;
			break;
		case 't':
			test(optarg);
			break;
		case 'h':
			usage();
			break;
		default:
			usage();
			break;
	};

	if (event_init(server) < 0) {
		return -1;
	}

	(void)ev_run();
	
	INFO("event_run over !\n");

	return 0;
}

