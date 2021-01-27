#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "simple_proto.h"
#include "mem.h"
#include "events.h"
#include "crypto.h"
#include "dh_group.h"
#include "local_config.h"

#define SIMP_VERSION_1 1

#define BUF_SIZE	20480
#define MAX_USER_LEN	50
#define VPN_PACKED __attribute__((aligned (1)))
#define MAX_KEY_SIZE	16

struct cmd_key_st {
	uint8_t version;
	uint16_t klen;
	uint8_t pubkey[0];
} VPN_PACKED;

struct cmd_auth_c_st {
	char user[MAX_USER_LEN];
	char pwd[MAX_USER_LEN];
} VPN_PACKED;

struct cmd_auth_r_st {
	uint16_t code;
	uint32_t reserve;
} VPN_PACKED;

/*
struct cmd_config_st {

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


typedef int (*do_cmd)(ser_cli_node *sc, uint8_t *data, uint16_t dlen);

static int cmd_key_send(ser_cli_node *sc);
static int cmd_auth_c_send(ser_cli_node *sc);
static int on_cmd_key(ser_cli_node *sc, uint8_t *data, uint16_t dlen);
static int on_cmd_auth_c(ser_cli_node *sc, uint8_t *data, uint16_t dlen);
static int on_cmd_auth_r(ser_cli_node *sc, uint8_t *data, uint16_t dlen);

enum {
	CMD_BEGIN,
	CMD_KEY,
	CMD_AUTH_C,
	CMD_AUTH_R,
	CMD_END
};

#define CMD_ENC_BEGIN CMD_AUTH_C
#define CMD_ENC_END CMD_END

struct cmd_map_st {
	int cmd;
	do_cmd fn;
};

static struct cmd_map_st s_do_cmd[] = {
					{CMD_BEGIN,		NULL},
					{CMD_KEY, 		on_cmd_key},
					{CMD_AUTH_C, 	on_cmd_auth_c},
					{CMD_AUTH_R, 	on_cmd_auth_r},
					{CMD_END,		NULL}
				};

struct cmd_desc_st {
	int cmd;
	const char *desc;
};

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

	if (hdr->cmd >= CMD_ENC_BEGIN && hdr->cmd < CMD_ENC_END) {
		if (crypto_decrypt(sc->crypt, hdr->data, &size) < 0 ||
				size != hdr->old_len) {
			DEBUG("decrypt failed: size: %u, old_len: %u", size, hdr->old_len);
			return -1;
		}
	}
	
	return s_do_cmd[hdr->cmd].fn(sc, hdr->data, size);
}


int start_connect(ser_cli_node *sc)
{
	return sc ? cmd_key_send(sc) : -1;
}

static int data_send(int sock, uint8_t *data, uint16_t len)
{
	while (len) {
		int ret = write(sock, data, len);
		if (ret < 0 || ret > len) {
			return -1;
		}

		len -= ret;
	}

	return 0;
}

static int cmd_send(const ser_cli_node *sc, uint16_t cmd, uint8_t *buf, uint32_t len)
{
	int enc = (cmd >= CMD_ENC_BEGIN && cmd < CMD_END) ? 1 : 0;
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

	if (data_send(sc->sock, (uint8_t *)hdr, sizeof(struct cmd_head_st) + dlen) < 0) {
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
	
	snprintf((char*)&ac.user, sizeof(ac.user), "%s", get_branch_user());
	snprintf((char*)&ac.pwd, sizeof(ac.pwd), "%s", get_branch_pwd());
	
	DEBUG("cmd auth_c send: user: %s", ac.user);
	return cmd_send(sc, CMD_AUTH_C, (uint8_t*)&ac, sizeof(struct cmd_auth_c_st));
}

static int cmd_auth_r_send(ser_cli_node *sc, uint16_t code)
{
	struct cmd_auth_r_st ar;
	ar.code = code;
	
	DEBUG("cmd auth_r send: code: %u", ar.code);
	return cmd_send(sc, CMD_AUTH_R, (uint8_t*)&ar, sizeof(struct cmd_auth_r_st));
}

static int on_cmd_auth_c(ser_cli_node *sc, uint8_t *data, uint16_t dlen)
{
	if (dlen != sizeof(struct cmd_auth_c_st)) {
		DEBUG("cmd auth_c invalid: dlen: %u, expected: %u", dlen, (uint32_t)sizeof(struct cmd_auth_c_st));
		return -1;
	}

	struct cmd_auth_c_st *ac = (struct cmd_auth_c_st *)data;
	DEBUG("on cmd auth_c: user: %s", ac->user);

	//TODO:check user/pwd
	INFO("client auth passed: %s", ac->user);

	return cmd_auth_r_send(sc, 0);
}

static int on_cmd_auth_r(ser_cli_node *sc, uint8_t *data, uint16_t dlen)
{
	if (dlen != sizeof(struct cmd_auth_r_st)) {
		DEBUG("cmd auth_r invalid: dlen: %u, expected: %u", dlen, (uint32_t)sizeof(struct cmd_auth_r_st));
		return -1;
	}

	struct cmd_auth_r_st *ar = (struct cmd_auth_r_st *)data;
	if (ar->code) {
		WARN("recv server response: auth failed: %u", ar->code);
		return -1;
	}

	INFO("auth passed");
	return 0;
}