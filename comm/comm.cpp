#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "comm.h"


struct tm * get_local_time()
{
	time_t t;
	time(&t);

	struct tm *stm = localtime(&t);;
	return stm;
}

const char * ip2str(uint32_t ip, char *buf, uint32_t size)
{
	const char *str = inet_ntop(AF_INET, &ip, buf, size);
	return str ?: "";
}

uint32_t str2ip(const char *str)
{
	if (!str)
		return 0;

	uint32_t ip;
	if (inet_pton(AF_INET, str, &ip) < 0) {
		return 0;
	}
	
	return ip;
}