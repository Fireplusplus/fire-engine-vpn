#ifndef __PROTO_20210215__
#define __PROTO_20210215__

#include <stdint.h>

#define BUF_SIZE	20480
#define VPN_PACKED __attribute__((aligned (1)))

struct cmd_tunnel_st {
	uint32_t dst_ip;
	short dst_port;
	int32_t seed;
	uint32_t klen;
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

struct cmd_head_st {
	uint16_t cmd;
	uint16_t cmd_check;		/* ~cmd */
	uint16_t old_len;
	uint16_t data_len;
	uint32_t reserve;
	uint8_t data[0];
};

enum {
	CMD_BEGIN,
	CMD_KEY,
	CMD_AUTH_C,
	CMD_AUTH_R,

	CMD_CONN = 9,
	CMD_END = 19
};

#define CMD_ENC_BEGIN CMD_AUTH_C
#define CMD_ENC_END CMD_AUTH_R

#endif
