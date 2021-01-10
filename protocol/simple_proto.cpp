#include <stdint.h>

#include "simple_proto.h"

#define MAX_USER_LEN 50
#define VPN_PACKED __attribute__((aligned (1)))

struct cmd_version_st {
	uint8_t version;
	uint16_t klen;
	uint8_t pubkey[0];
} VPN_PACKED;

struct cmd_auth_c_st {
	char user[MAX_USER_LEN];
	char pwd[MAX_USER_LEN];
} VPN_PACKED;

struct cmd_auth_r_st {
	uint8_t code;
	uint32_t reserve;
} VPN_PACKED;

struct cmd_config_st {

} VPN_PACKED;

