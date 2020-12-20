#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "events.h"
#include "dh_group.h"


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
	openssl_init();

	DH *dh1 = dh_create();
	DH *dh2 = dh_create();

	unsigned char pubkey1[1024];
	unsigned char pubkey2[1024];
	unsigned int sz1 = sizeof(pubkey1), sz2 = sizeof(pubkey2);
	dh_pubkey(dh1, pubkey1, &sz1);
	dh_pubkey(dh2, pubkey2, &sz2);

	unsigned char sharekey1[1024];
	unsigned char sharekey2[1024];
	unsigned s1 = sizeof(sharekey1), s2 = sizeof(sharekey2);

	dh_sharekey(dh1, pubkey2, sz1, sharekey1, &s1);
	dh_sharekey(dh2, pubkey1, sz1, sharekey2, &s2);
	
	DUMP_HEX("dh1", sharekey1, s1);
	DUMP_HEX("dh2", sharekey2, s2);


	return 0;
}

