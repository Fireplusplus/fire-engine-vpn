#include <assert.h>
#include "proto.h"

const char * s_type2str[] = {
									"PKT_BEGIN",
									"PKT_KEY",
									"PKT_AUTH_C",
									"PKT_AUTH_R",
									"PKT_CONN",
									"PKT_DATA",
									"PKT_ECHO_REQ",
									"PKT_ECHO_REP",
									"PKT_END",
								};

const char * pkt_type2str(uint8_t type)
{
	assert(type < PKT_END);
	return s_type2str[type];
}