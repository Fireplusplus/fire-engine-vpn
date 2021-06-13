#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "fd_send.h"
#include "proto.h"
#include "log.h"

static const char * s_type2str[] = {
									"PKT_BEGIN",
									"PKT_KEY",
									"PKT_AUTH_C",
									"PKT_AUTH_R",
									"PKT_CONN_SET",
									"PKT_CONN_GET",
									"PKT_DATA",
									"PKT_ECHO_REQ",
									"PKT_ECHO_REP",
									"PKT_END",
								};

static uint8_t s_type2enc[] = {
									0, //"PKT_BEGIN",
									0, //"PKT_KEY",
									1, //"PKT_AUTH_C",
									1, //"PKT_AUTH_R",
									0, //"PKT_CONN_SET",
									0, //"PKT_CONN_GET",
									1, //"PKT_DATA",
									0, //"PKT_ECHO_REQ",
									0, //"PKT_ECHO_REP",
									0, //"PKT_END",
								};

const char * pkt_type2str(uint8_t type)
{
	assert(type < PKT_END);
	return s_type2str[type];
}

static inline int pack_pkt(uint8_t type, struct crypto_st *crypt, 
				uint8_t *data, uint16_t len, uint8_t *buf, uint32_t *size)
{
	struct vpn_head_st *hdr = (struct vpn_head_st *)buf;
	uint32_t dsize = *size - sizeof(*hdr);
	uint8_t enc = s_type2enc[type];

	if (!enc) {
		memcpy(hdr->data, data, len);

		hdr->enc = 0;
		hdr->data_len = len;
	} else {
		if (crypto_encrypt(crypt, data, len, hdr->data, &dsize) < 0)
			return -1;

		hdr->enc = 1;
		hdr->data_len = dsize;
	}

	hdr->old_len = len;
	hdr->type = type;
	hdr->_type = ~type;
	hdr->reserve = 0;

	*size = hdr->data_len + sizeof(*hdr);
	return 0;
}

int pkt_send(int fd, uint8_t type, struct crypto_st *crypt, uint8_t *data, uint16_t len)
{
	uint8_t buf[PKT_SIZE];
	uint32_t size = sizeof(buf);

	if (pack_pkt(type, crypt, data, len, buf, &size) < 0)
		return -1;

	return send(fd, buf, size, 0);
}

int pkt_recv(int fd, struct crypto_st *crypt, uint8_t *buf, uint16_t size)
{
	struct vpn_head_st *hdr = (struct vpn_head_st *)buf;
	
	int ret = read(fd, buf, size);
	if (ret <= 0) {
		return ret; 
	}
	
	if (ret < (int)hdr->data_len + (int)sizeof(*hdr)) {
		DEBUG("drop invalid size: type: %u, ret: %d, expect: %d", 
				hdr->type, ret, (int)hdr->data_len + (int)sizeof(*hdr));
		return -1;
	}

	if (hdr->type <= PKT_BEGIN || hdr->type >= PKT_END) {
		DEBUG("drop unknown type: %u", hdr->type);
		return -1;
	}

	if ((uint16_t)~(hdr->type) != hdr->_type) {
		DEBUG("drop invalid type: type: %u, _type: %u", hdr->type, hdr->_type);
		return -1;
	}

	uint32_t dsize = hdr->data_len;

	if (!hdr->enc) {
		if (s_type2enc[hdr->type]) {
			DEBUG("drop no enc: %s", pkt_type2str(hdr->type));
			return -1;
		}
	} else if (!crypt) {
		DEBUG("drop no crypt: %s", pkt_type2str(hdr->type));
		return -1;
	} else if (crypto_decrypt(crypt, hdr->data, &dsize) < 0) {
		DEBUG("drop decryupt failed: %s", pkt_type2str(hdr->type));
		return -1;
	}

	if (hdr->old_len != dsize) {
		DEBUG("drop invalid dec size: %s, dsize: %u, expect: %u", 
			pkt_type2str(hdr->type), dsize, hdr->old_len);
		return -1;
	}

	if (hdr->type != PKT_DATA)
		DEBUG("recv cmd: %s", pkt_type2str(hdr->type));

	return ret;
}

int conn_send(int fd, uint8_t type, struct crypto_st *crypt, uint8_t *data, uint16_t len, int fd_conn)
{
	uint8_t buf[PKT_SIZE];
	uint32_t size = sizeof(buf);

	if (pack_pkt(type, crypt, data, len, buf, &size) < 0)
		return -1;

	return send_fd(fd, fd_conn, buf, size);
}
