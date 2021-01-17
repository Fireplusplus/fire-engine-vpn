#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "simple_proto.h"
#include "mem.h"
#include "events.h"
#include "crypto.h"
#include "dh_group.h"

#define SIMP_VERSION_1 1

#define BUF_SIZE 20480
#define MAX_USER_LEN 50
#define VPN_PACKED __attribute__((aligned (1)))

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
	uint8_t code;
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

enum {
	CMD_BEGIN,

	CMD_KEY,
	CMD_AUTH_C,
	CMD_AUTH_R,

	CMD_END
};

#define CMD_ENC_BEGIN CMD_AUTH_C
#define CMD_ENC_END CMD_END

int data_send(int sock, uint8_t *data, uint16_t len)
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

int cmd_send(const ser_cli_node *sc, uint16_t cmd, uint8_t *buf, uint32_t len)
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
		memcpy(hdr->data, buf, dlen);
	} else {
		uint32_t olen = dlen;
		if (!crypto_encrypt(sc->crypt, buf, len, hdr->data, &olen)
				|| olen != dlen) {
			free(hdr);
			return -1;
		}
	}

	if (data_send(sc->sock, (uint8_t *)hdr, sizeof(struct cmd_head_st) + dlen) < 0) {
		free(hdr);
		return -1;
	}

	free(hdr);
	return 0;
}

int cmd_key_send(ser_cli_node *sc)
{
	if (!sc)
		return -1;
	
	uint8_t buf[BUF_SIZE];
	struct cmd_key_st *key = (struct cmd_key_st *)&buf;
	
	dh_destroy(sc->dh);
	sc->dh = dh_create();
	if (!sc->dh)
		return -1;
	
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
	
	return cmd_send(sc, CMD_KEY, (uint8_t*)key, sizeof(struct cmd_key_st) + ksize);

failed:
	dh_destroy(sc->dh);
	return 0;
}