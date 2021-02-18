#ifndef __PROTO_20210215__
#define __PROTO_20210215__

#include <stdint.h>

#define PKT_SIZE	65535
#define BUF_SIZE	20480
#define MAX_USER_LEN	50
#define VPN_PACKED __attribute__((aligned (1)))

struct cmd_tunnel_st {
	uint32_t dst_ip;
	short dst_port;
	int32_t seed;
	uint32_t klen;
	char user[MAX_USER_LEN];
	uint32_t reserve;
	uint8_t pubkey[0];
};

/*
struct subnet_st {
	uint32_t ip;
	uint32_t mask;
} VPN_PACKED;

struct cmd_config_st {
	uint16_t cnt;
	uint8_t data[0];
} VPN_PACKED;
*/

enum {
	CMD_BEGIN,
	CMD_KEY,
	CMD_AUTH_C,
	CMD_AUTH_R,

	CMD_CONN = 9,
	CMD_END = 19
};

#endif
