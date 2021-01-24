#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "events.h"
#include "dh_group.h"
#include "crypto.h"


void usage()
{
	printf("Usage: ./server [s|c]\n");
	exit(0);
}

void test(const char *opt)
{
	INFO("test: %s", opt);
	
	if (strncmp(opt, "crypto", strlen("crypto")) == 0)
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
		default:
			usage();
			return 0;
	};
	
	if (event_init(server) < 0) {
		return -1;
	}

	(void)event_run();
	
	INFO("event_run over !\n");

	return 0;
}

