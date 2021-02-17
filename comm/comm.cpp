#include "comm.h"

struct tm * get_local_time()
{
	time_t t;
	time(&t);

	struct tm *stm = localtime(&t);;
	return stm;
}