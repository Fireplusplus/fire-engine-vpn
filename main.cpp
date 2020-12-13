#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "events.h"


void usage()
{
	printf("Usage: ./server [s|c]\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	if (argc <= 1)
		usage();
	
	if (event_init(argv[1][0] == 's' ? 1 : 0) < 0) {
		printf("event init failed\n");
		return -1;
	}

	(void)event_run();
	
	printf("event_run over !\n");
	return 0;
}

