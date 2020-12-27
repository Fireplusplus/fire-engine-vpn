#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "events.h"
#include "dh_group.h"
#include "crypto.h"


void usage()
{
	printf("Usage: ./server [s|c]\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	/*if (argc <= 1)
		usage();
	
	if (event_init(argv[1][0] == 's' ? 1 : 0) < 0) {
		return -1;
	}

	(void)event_run();
	
	INFO("event_run over !\n");*/

	crypto_example();

	return 0;
}

