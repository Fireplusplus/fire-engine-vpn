#ifndef __PROTO_20210215__
#define __PROTO_20210215__

#include <stdint.h>

#define PKT_SIZE	65535
#define BUF_SIZE	20480
#define MAX_USER_LEN	50
#define MAX_NETS_CNT	10
#define VPN_PACKED __attribute__((aligned (1)))


struct net_st {
	uint32_t ip;
	uint32_t mask;
} VPN_PACKED;

struct cmd_tunnel_st {
	uint32_t dst_ip;
	short dst_port;
	uint32_t seed;
	uint32_t klen;
	char user[MAX_USER_LEN];
	struct net_st nets[MAX_NETS_CNT];
	uint32_t reserve;
	uint8_t pubkey[0];
};

struct vpn_head_st {
	uint16_t type;				/* 数据包类型 */
	uint16_t _type;				/* ~type */
	uint16_t old_len;			/* 内层数据加密前长度 */
	uint16_t data_len;			/* 内层数据加密后长度 */
	uint32_t reserve;
	uint8_t data[0];
} VPN_PACKED;

enum pkt_type {
	PKT_BEGIN,
	PKT_KEY,
	PKT_AUTH_C,
	PKT_AUTH_R,
	PKT_CONN_SET,
	PKT_CONN_GET,
	PKT_DATA,
	PKT_ECHO_REQ,
	PKT_ECHO_REP,
	PKT_END
};

const char * pkt_type2str(uint8_t type);

#endif
