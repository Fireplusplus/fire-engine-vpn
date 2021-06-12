#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "simple_proto.h"
#include "mem.h"
#include "events.h"
#include "crypto.h"
#include "dh_group.h"
#include "local_config.h"
#include "ipc.h"
#include "fd_send.h"
#include "proto.h"
#include "config.h"
#include "tunnel_route.CPP"

#define SIMP_VERSION_1 1
#define MAX_KEY_SIZE	16

struct cmd_key_st {
	uint8_t version;
	uint16_t klen;
	uint32_t reserve;
	uint8_t pubkey[0];
} VPN_PACKED;

struct cmd_auth_c_st {
	char user[MAX_USER_LEN];
	char pwd[MAX_USER_LEN];
	uint32_t reserve;
} VPN_PACKED;

struct cmd_auth_r_st {
	uint16_t code;
	int32_t seed;		/* 随机种子,客户端建立数据通道时发给服务端校验 */
	int netcnt;
	uint32_t reserve;
	uint8_t data[0];
} VPN_PACKED;

struct cmd_head_st {
	uint16_t cmd;
	uint16_t cmd_check;		/* ~cmd */
	uint16_t old_len;
	uint16_t data_len;
	uint32_t reserve;
	uint8_t data[0];
} VPN_PACKED;


typedef int (*do_cmd)(ser_cli_node *sc, uint8_t *data, uint16_t dlen);

static int cmd_key_send(ser_cli_node *sc);
static int cmd_auth_c_send(ser_cli_node *sc);
static int cmd_auth_r_send(ser_cli_node *sc, uint16_t code);
static int on_cmd_key(ser_cli_node *sc, uint8_t *data, uint16_t dlen);
static int on_cmd_auth_c(ser_cli_node *sc, uint8_t *data, uint16_t dlen);
static int on_cmd_auth_r(ser_cli_node *sc, uint8_t *data, uint16_t dlen);
static int conn_notify(ser_cli_node *sc, net_st *nets, int netcnt);


#define CMD_ENC_BEGIN CMD_AUTH_C
#define CMD_ENC_END CMD_AUTH_R

struct cmd_map_st {
	int cmd;
	do_cmd fn;
};

static struct cmd_map_st s_do_cmd[CMD_END] = {
					{CMD_BEGIN,		NULL},
					{CMD_KEY, 		on_cmd_key},
					{CMD_AUTH_C, 	on_cmd_auth_c},
					{CMD_AUTH_R, 	on_cmd_auth_r},
				};

struct cmd_desc_st {
	int cmd;
	const char *desc;
};

static ipc_st *s_tunnel_ipc;

static struct cmd_desc_st s_cmd_desc[] = {
					{CMD_BEGIN,		"CMD_BEGIN"},
					{CMD_KEY, 		"CMD_KEY"},
					{CMD_AUTH_C, 	"CMD_AUTH_C"},
					{CMD_AUTH_R, 	"CMD_AUTH_R"},
					{CMD_END,		"CMD_END"}
				};

int on_cmd(ser_cli_node *sc, uint8_t *data, uint16_t dlen)
{
	if (!sc || !data || !dlen)
		return -1;
	
	struct cmd_head_st *hdr = (struct cmd_head_st *)data;
	if (hdr->cmd <= CMD_BEGIN || hdr->cmd >= CMD_END ||
			hdr->cmd != (uint16_t)~(hdr->cmd_check)) {
		DEBUG("invalid cmd head: cmd: %u, cmd_check: %u", hdr->cmd, hdr->cmd_check);
		return -1;
	}

	DEBUG("recv cmd: %s, old_len: %u, data_len: %u", s_cmd_desc[hdr->cmd].desc, hdr->old_len, hdr->data_len);

	uint32_t size = hdr->data_len;

	if (hdr->cmd >= CMD_ENC_BEGIN && hdr->cmd <= CMD_ENC_END) {
		if (crypto_decrypt(sc->crypt, hdr->data, &size) < 0 ||
				size != hdr->old_len) {
			DEBUG("decrypt failed: size: %u, old_len: %u", size, hdr->old_len);
			return -1;
		}
	}
	
	if (!s_do_cmd[hdr->cmd].fn) {
		INFO("unknown cmd: %u", hdr->cmd);
		return -1;
	}

	return s_do_cmd[hdr->cmd].fn(sc, hdr->data, size);
}


int start_connect(ser_cli_node *sc)
{
	return sc ? cmd_key_send(sc) : -1;
}

static int cmd_send(const ser_cli_node *sc, uint16_t cmd, uint8_t *buf, uint32_t len)
{
	int enc = (cmd >= CMD_ENC_BEGIN && cmd <= CMD_ENC_END) ? 1 : 0;
	uint32_t dlen = enc ? crypto_encrypt_size(len) : len;
	struct cmd_head_st *hdr;

	if (enc && !sc->crypt) {
		DEBUG("need encrypt but no crypt handle !");
		return -1;
	}
	
	hdr = (struct cmd_head_st *)alloc_die(sizeof(struct cmd_head_st) + dlen);
	hdr->cmd = cmd;
	hdr->cmd_check = ~cmd;
	hdr->old_len = len;
	hdr->data_len = dlen;

	if (!enc) {
		memcpy(hdr->data, buf, len);
	} else {
		uint32_t olen = dlen;
		if (crypto_encrypt(sc->crypt, buf, len, hdr->data, &olen) < 0
				|| olen != dlen) {
			DEBUG("encrypt failed: olen: %u, dlen: %u", olen, dlen);
			free(hdr);
			return -1;
		}
	}

	if (ipc_send(sc->ipc, (uint8_t *)hdr, sizeof(struct cmd_head_st) + dlen) < 0) {
		DEBUG("data send failed");
		free(hdr);
		return -1;
	}

	DEBUG("send cmd: %s, old_len: %u, data_len: %u", s_cmd_desc[hdr->cmd].desc, hdr->old_len, hdr->data_len);
	free(hdr);
	return 0;
}

static int cmd_key_send(ser_cli_node *sc)
{
	uint8_t buf[BUF_SIZE];
	struct cmd_key_st *key = (struct cmd_key_st *)&buf;

	sc->status = sc->server ? SC_KEY_R_SEND : SC_KEY_C_SEND;
	
	if (!sc->dh)
		sc->dh = dh_create();
	
	uint32_t ksize = dh_keysize(sc->dh);
	if (ksize > sizeof(buf) - sizeof(struct cmd_key_st)) {
		DEBUG("buf too small: buf size: %lu, expect size: %u", 
			(sizeof(buf) - sizeof(struct cmd_key_st)), ksize);
		return -1;
	}

	key->version = SIMP_VERSION_1;
	key->klen = ksize;

	if (dh_pubkey(sc->dh, key->pubkey, &ksize) < 0 ||
			ksize != key->klen) {
		goto failed;
	}
	
	DEBUG("cmd key send: version: %u, klen: %u", key->version, key->klen);
	return cmd_send(sc, CMD_KEY, (uint8_t*)key, sizeof(struct cmd_key_st) + ksize);

failed:
	dh_destroy(sc->dh);
	sc->dh = NULL;
	return -1;
}

static int on_cmd_key(ser_cli_node *sc, uint8_t *data, uint16_t dlen)
{
	struct cmd_key_st *key = (struct cmd_key_st *)data;
	if (dlen != sizeof(struct cmd_key_st) + key->klen) {
		DEBUG("cmd key invalid: dlen: %u, expected: %u", dlen, (uint32_t)sizeof(struct cmd_key_st) + key->klen);
		return -1;
	}

	DEBUG("on cmd key: version: %u, klen: %u", key->version, key->klen);

	if (sc->server) {
		dh_destroy(sc->dh);
		sc->dh = dh_create();
		if (!sc->dh)
			return -1;
	}

	/* 获取dh群共享密钥 */
	uint8_t sharekey[1024];
	uint32_t klen = sizeof(sharekey);
	if (dh_sharekey(sc->dh, key->pubkey, key->klen, 
		(uint8_t*)&sharekey, &klen) < 0) {
		WARN("on cmd key failed: can't generate share key");
		return -1;
	}

	/* 创建加密器 */
	crypto_destroy(sc->crypt);
	sc->crypt = crypto_create((uint8_t*)sharekey, MIN(klen, MAX_KEY_SIZE));
	if (!sc->crypt) {
		WARN("on cmd key failed: can't create encryptor");
		return -1;
	}

	if (sc->server)
		return cmd_key_send(sc);
	
	return cmd_auth_c_send(sc);
}

static int cmd_auth_c_send(ser_cli_node *sc)
{
	struct cmd_auth_c_st ac;
	
	sc->status = SC_AUTH_C_SEND;
	snprintf((char*)&ac.user, sizeof(ac.user), "%s", get_branch_user());
	snprintf((char*)&ac.pwd, sizeof(ac.pwd), "%s", get_branch_pwd());
	
	DEBUG("cmd auth_c send: user: %s", ac.user);
	return cmd_send(sc, CMD_AUTH_C, (uint8_t*)&ac, sizeof(struct cmd_auth_c_st));
}

static int on_cmd_auth_c(ser_cli_node *sc, uint8_t *data, uint16_t dlen)
{
	if (dlen != sizeof(struct cmd_auth_c_st)) {
		DEBUG("cmd auth_c invalid: dlen: %u, expected: %u", dlen, (uint32_t)sizeof(struct cmd_auth_c_st));
		return -1;
	}

	struct cmd_auth_c_st *ac = (struct cmd_auth_c_st *)data;
	DEBUG("on cmd auth_c: user: %s", ac->user);

	sc->user = get_user(ac->user);
	if (!sc->user) {
		WARN("client auth failed: not found user(%s)", ac->user);
		return -1;
	}

	//check user/pwd
	if (check_user(sc->user, ac->pwd) < 0) {
		WARN("client auth failed: %s", ac->user);
		cmd_auth_r_send(sc, 1);
		return -1;
	}

	INFO("client auth passed: %s", ac->user);

	if (cmd_auth_r_send(sc, 0) < 0) {
		return -1;
	}

	return conn_notify(sc, NULL, 0);
}

static int cmd_auth_r_send(ser_cli_node *sc, uint16_t code)
{
	uint8_t buf[BUF_SIZE];
	struct cmd_auth_r_st *ar = (struct cmd_auth_r_st *)buf;

	sc->status = SC_AUTH_R_SEND;
	ar->code = code;
	ar->seed = safe_rand();

	ar->netcnt = get_server_net((char *)ar->data, sizeof(buf) - sizeof(*ar));
	if (ar->netcnt < 0) {
		DEBUG("get user net failed");
		return -1;
	}

	DEBUG("net count: %d", ar->netcnt);

	sc->seed = ar->seed;

	char user_nets[BUF_SIZE];
	int cnt = get_user_net(sc->user, user_nets, sizeof(user_nets));

	/* 添加用户路由 */
	if (tunnel_route_add(cnt, (struct net_st *)user_nets) < 0) {
		WARN("route to client add failed !");
		return -1;
	}
	
	DEBUG("cmd auth_r send: code: %u", ar->code);
	return cmd_send(sc, CMD_AUTH_R, (uint8_t*)ar, sizeof(*ar) + ar->netcnt * sizeof(struct net_st));
}

static int on_cmd_auth_r(ser_cli_node *sc, uint8_t *data, uint16_t dlen)
{
	struct cmd_auth_r_st *ar = (struct cmd_auth_r_st *)data;
	if (dlen != sizeof(*ar) + ar->netcnt * sizeof(struct net_st)) {
		DEBUG("cmd auth_r invalid: dlen: %u, expected: %u", dlen, 
			(uint32_t)(sizeof(*ar) + ar->netcnt * sizeof(struct net_st)));
		return -1;
	}

	if (ar->code) {
		WARN("recv server response: auth failed: %u", ar->code);
		return -1;
	}

	/* 添加发往server的路由 */
	if (tunnel_route_add(ar->netcnt, (struct net_st *)ar->data) < 0) {
		WARN("route to server add failed !");
		return -1;
	}

	sc->seed = ar->seed;

	INFO("auth passed");

	conn_notify(sc, (struct net_st *)ar->data, ar->netcnt);
	return 0;
}

static void reset_tunnel_handle_block(int server)
{
	const char *addr = get_tunnel_addr(server);

	ipc_destroy(s_tunnel_ipc);
	s_tunnel_ipc = NULL;

	do {
		s_tunnel_ipc = ipc_client_create(AF_UNIX, NULL, 0, addr, 0);
		sleep(1);
	} while (!s_tunnel_ipc);
}

/* 通知新连接给tunnel_manage */
static int conn_notify(ser_cli_node *sc, struct net_st *nets, int netcnt)
{
	uint8_t buf[BUF_SIZE];
	struct cmd_tunnel_st *tn = (struct cmd_tunnel_st *)buf;

	if (ipc_peer_addr(sc->ipc, &tn->dst_ip, &tn->dst_port) < 0) {
		return -1;
	}

	int ret = crypto_key(sc->crypt, (uint8_t*)&tn->pubkey, sizeof(buf) - sizeof(struct cmd_tunnel_st));
	if (ret < 0) {
		return -1;
	}

	int cnt;
	if (sc->server) {
		cnt = get_user_net(sc->user, (char*)tn->nets, sizeof(tn->nets));
	} else {
		memcpy((char*)tn->nets, nets, MIN(netcnt, MAX_NETS_CNT) * sizeof(*nets));
		cnt = netcnt;
	}

	DEBUG("nets cnt: %d", cnt);

	tn->klen = ret;
	tn->seed = sc->seed;
	snprintf(tn->user, sizeof(tn->user), "%s", 
		sc->user ? get_user_name(sc->user) : get_branch_user());

	/* 发送文件描述符到tunnel_manage */
	if (send_fd(ipc_fd(s_tunnel_ipc), ipc_fd(sc->ipc), 
			buf, sizeof(struct cmd_tunnel_st) + tn->klen) < 0) {
		reset_tunnel_handle_block(sc->server);
		return -1;
	}

	INFO("notify tunnel manage to create tunnel");
	sc->status = SC_SUCCESS;

	return 0;
}

int proto_init(int server)
{
	reset_tunnel_handle_block(server);
	return 0;
}

