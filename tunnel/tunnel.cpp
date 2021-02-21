#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <semaphore.h>

#include <iostream>
#include <unordered_map>

#include "tunnel.h"
#include "log.h"
#include "tun.h"
#include "crypto.h"
#include "local_config.h"
#include "ipc.h"
#include "ev.h"
#include "proto.h"
#include "fd_send.h"
#include "ring_buf.h"

using namespace std;

/*
          ring_buf1 —— thread1 —— enc_output
        /
raw_input —— ring_buf2 —— thread2 —— enc_output
        \
          ring_buf3 ——  thread3 —— enc_output

            ev_base1 —— thread1 —— raw_output
          /
enc_input —— ev_base2 —— thread2 —— raw_output
          \
            ev_base3 —— thread3 ——  raw_output
*/


struct tunnel_manage_st {
	int server;			/* 是否服务端 */
	int raw_fd;			/* 原始输入句柄 */
	int enc_fd;			/* 加密流句柄 */
	ipc_st *recv;		/* 同vpn_manage的通信句柄 */
};

struct tunnel_st {
	int fd;							/* 加密流通信句柄 */
	int seed;						/* 随机种子 */
	struct crypto_st *crypt;		/* 加密器 */
	char user[MAX_USER_LEN];		/* 用户名 */
	uint64_t last_active;			/* 上次活跃时间 */
};

struct raw_data_st {
	int len;
	struct tun_pi pi;
	uint8_t data[0];
};

struct vpn_head_st {
	uint16_t old_len;
	uint16_t data_len;
	uint32_t reserve;
	uint8_t data[0];
} VPN_PACKED;


#define RING_BUF_SIZE		1024
#define RAW_THREAD_MAX		8

static struct tunnel_manage_st s_tunnel_manage;					/* 全局管理信息 */
static unordered_map<int, tunnel_st*> s_tunnel_list;			/* 隧道信息缓存表 */
static struct ring_buf_st * s_raw_bufs[RAW_THREAD_MAX];			/* 内网数据包缓冲区 */
static pthread_t s_raw_threads[RAW_THREAD_MAX];					/* 内网数据处理线程 */
static sem_t s_raw_read_sems[RAW_THREAD_MAX];					/* 内网数据包缓冲可读信号量 */
static sem_t s_raw_write_sems[RAW_THREAD_MAX];					/* 内网数据包缓冲可写信号量 */

#define RAW_IDX_BY_TUNNEL(tl)	(tl->seed % RAW_THREAD_MAX)

#define RAW_WAIT_READ_IDX(idx)	sem_wait(&s_raw_read_sems[idx])
#define RAW_WAIT_WRITE_IDX(idx)	sem_wait(&s_raw_write_sems[idx])
#define RAW_POST_READ_IDX(idx)	sem_post(&s_raw_read_sems[idx])
#define RAW_POST_WRITE_IDX(idx)	sem_post(&s_raw_write_sems[idx])
	

static void raw_input(int fd, short event, void *arg);
static int raw_output(struct tunnel_st *tl, uint8_t *data, uint32_t size);
static void enc_input(int fd, short event, void *arg);
static int enc_output(struct tunnel_st *tl, struct raw_data_st *pkt);

/* TODO: 添加定时清理 */
static void tunnel_destroy(struct tunnel_st *tl)
{
	ev_unregister(tl->fd);

	unordered_map<int, tunnel_st*>::iterator it= s_tunnel_list.find(tl->fd);
	if (it != s_tunnel_list.end())
		s_tunnel_list.erase(it);
	
	crypto_destroy(tl->crypt);
	
	if (tl->fd)
		close(tl->fd);
	
	INFO("conn(%s) fd(%d) is broken", tl->user, tl->fd);
	free(tl);
}

static tunnel_st * tunnel_create(int fd, uint8_t *buf, int size)
{
	struct cmd_tunnel_st *cmd = (struct cmd_tunnel_st *)buf;
	if (!buf || size != (int)(cmd->klen + sizeof(struct cmd_tunnel_st))) {
		DEBUG("invalid tunnel cmd size: %d, expect: %lu", size, cmd->klen + sizeof(struct cmd_tunnel_st));
		return NULL;
	}

	unordered_map<int, tunnel_st*>::iterator it= s_tunnel_list.find(fd);
	if (it != s_tunnel_list.end()) {
		WARN("fd(%d) is already in use, user(%s) established failed", fd, cmd->user);
		return NULL;
	}

	tunnel_st *tl = (tunnel_st*)calloc(1, sizeof(tunnel_st));
	if (!tl)
		return NULL;
	
	memcpy(tl->user, cmd->user, sizeof(tl->user));
	tl->fd = fd;
	tl->seed = cmd->seed;
	tl->crypt = crypto_create(cmd->pubkey, cmd->klen);
	if (!tl->crypt)
		goto failed;
	
	if (ev_register(fd, enc_input, tl) < 0)
		goto failed;
	
	s_tunnel_list[fd] = tl;
	INFO("conn(%s) fd(%d) established success", tl->user, tl->fd);
	return tl;

failed:
	tunnel_destroy(tl);
	return NULL;
}

/* 自定义event分发函数 */
uint32_t tunnel_ev_rss(int fd, void *arg)
{
	if (!arg)
		return EV_THREADS_NUM - 1;	/* raw独占最后一个线程 */
	
	struct tunnel_st *tl = (struct tunnel_st *)arg;
	return tl->seed % (EV_THREADS_NUM - 1);
}

/* 根据路由查询所属隧道 */
static struct tunnel_st * select_tunnel_by_rawpkt(uint8_t *pkt)
{
	if (s_tunnel_list.empty())
		return NULL;
	
	/* TODO: 根据路由查询所属隧道 */
	return s_tunnel_list.begin()->second;
}

/* 处理原始输入: 识别隧道, buf分发 */
static void raw_input(int fd, short event, void *arg)
{
	struct raw_data_st *pkt = (struct raw_data_st *)malloc(PKT_SIZE + sizeof(struct raw_data_st));
	if (!pkt) {
		DEBUG("raw input no memory");
		return;
	}

	pkt->len = read(fd, pkt, PKT_SIZE + sizeof(struct raw_data_st));	/* TODO: 阻塞读? */
	if (pkt->len <= 0) {
		DEBUG("raw read failed: %s", strerror(errno));
		free(pkt);
		return; 
	}

	if (pkt->pi.flags == TUN_PKT_STRIP) {
		DEBUG("drop raw: pkt too big: proto: %02x", ntohs(pkt->pi.proto));
		free(pkt);
		return;
	}

	if (pkt->pi.proto != 0x01)
		return;

	struct tunnel_st *tl = select_tunnel_by_rawpkt(pkt->data);
	if (!tl) {
		DEBUG("drop raw: not find tunnel: proto: %02x", ntohs(pkt->pi.proto));
		free(pkt);
		return;
	}

	int idx = RAW_IDX_BY_TUNNEL(tl);
	struct ring_buf_st *rb = s_raw_bufs[idx];

	RAW_WAIT_WRITE_IDX(idx);
	if (!enqueue(rb, pkt)) {
		DEBUG("drop raw: no ring cache: proto: %02x", ntohs(pkt->pi.proto));
		free(pkt);
		assert(0);	/* 有信号量调控不应该会没空间 */
		return;
	}
	RAW_POST_READ_IDX(idx);
}

static int raw_output(struct tunnel_st *tl, uint8_t *data, uint32_t size)
{
	if (!data || !size)
		return -1;

	int ret = write(s_tunnel_manage.raw_fd, data, size);
	if (ret <= 0) {
		DEBUG("drop raw: write failed");
		return -1;
	}

	return ret;
}

/* events回调, 在ev多线程处理 */
static void enc_input(int fd, short event, void *arg)
{
	uint8_t buf[PKT_SIZE];
	int ret = read(fd, buf, sizeof(buf));
	if (ret <= 0) {
		return; 
	}

	struct vpn_head_st *head = (struct vpn_head_st *)buf;
	if (ret != (int)head->data_len + (int)sizeof(*head)) {
		DEBUG("drop enc invalid size: ret: %d, expect: %d", ret, (int)head->data_len + (int)sizeof(*head));
		return;
	}

	struct tunnel_st *tl = (struct tunnel_st *)arg;
	uint32_t size = head->data_len;
	if (crypto_decrypt(tl->crypt, head->data, &size) < 0) {
		DEBUG("drop enc decryupt failed");
		return;
	}

	if (head->old_len != size) {
		DEBUG("drop enc invalid dec size: size: %u, expect: %u", size, head->old_len);
		return;
	}

	raw_output(tl, head->data, size);
}

static int enc_output(struct tunnel_st *tl, struct raw_data_st *pkt)
{
	uint8_t buf[PKT_SIZE];
	uint32_t size = sizeof(buf) - sizeof(struct vpn_head_st);

	struct vpn_head_st *head = (struct vpn_head_st *)buf;
	head->old_len = pkt->len - sizeof(struct raw_data_st);
	
	if (crypto_encrypt(tl->crypt, pkt->data, head->old_len,
					head->data, &size) < 0) {
		DEBUG("drop enc failed");
		return -1;
	}

	head->data_len = size;
	head->reserve = 0;
	
	return send(tl->fd, buf, size + sizeof(struct vpn_head_st), 0);
}

/* 消费内网数据: 封装-->加密-->发送 */
static void * raw_consumer(void *arg)
{
	int idx = (int)(uint64_t)arg;
	struct ring_buf_st *rb = (struct ring_buf_st *)s_raw_bufs[idx];

	while (1) {
		RAW_WAIT_READ_IDX(idx);
		struct raw_data_st *pkt = (struct raw_data_st *)dequeue(rb);
		if (!pkt) {
			assert(0);	/* 有信号量调控不应该会没数据 */
			continue;
		}
		RAW_POST_WRITE_IDX(idx);

		struct tunnel_st *tl = select_tunnel_by_rawpkt(pkt->data);
		if (!tl) {
			DEBUG("drop raw: no find tunnel: proto: %02x", ntohs(pkt->pi.proto));
			free(pkt);
			continue;
		}

		if (enc_output(tl, pkt) < 0) {
			DEBUG("drop raw: output failed: proto: %02x", ntohs(pkt->pi.proto));
			free(pkt);
			continue;
		}
	}
}

/* 接收vpn_managle发送的socket描述符, 建立隧道 */
void conn_listen()
{
	uint8_t buf[BUF_SIZE];
	int vpn_fd = ipc_fd(s_tunnel_manage.recv);
	int new_fd;
	
	while (1) {
		int size = sizeof(buf) / sizeof(buf[0]);

		if (recv_fd(vpn_fd, &new_fd, buf, &size) < 0) {
			sleep(3);
			continue;
		}

		(void)tunnel_create(new_fd, buf, size);
	}
}

int tunnel_init(int server, int nraw)
{
	const char *addr = get_tunnel_addr(server);
	remove(addr);

	ipc_st *listen = ipc_listener_create(AF_UNIX, addr, 0);
	if (!listen)
		return -1;
	
	do {
		s_tunnel_manage.recv = ipc_accept(listen);
		sleep(3);
	} while (!s_tunnel_manage.recv);
	
	ipc_destroy(listen);

	INFO("create tun: ip: %s", get_tun_ip());
	s_tunnel_manage.raw_fd = tun_init(get_tun_ip());
	if (s_tunnel_manage.raw_fd < 0) {
		ipc_destroy(s_tunnel_manage.recv);
		return -1;
	}

	if (ev_register(s_tunnel_manage.raw_fd, raw_input, NULL) < 0) {		/* 监听内网输入数据包 */
		ERROR("register raw input event failed");
		goto failed;
	}

	s_tunnel_manage.server = server;

	if (nraw <= 0 || nraw >= RAW_THREAD_MAX)
		nraw = 3;
	
	for (int i = 0; i < nraw; i++) {
		s_raw_bufs[i] = ring_buf_create(RING_BUF_SIZE);
		if (!s_raw_bufs[i])
			goto failed;
		
		if (pthread_create(&s_raw_threads[i], NULL, raw_consumer, (void*)(uint64_t)i) < 0) {
			ERROR("start thread failed");
			goto failed;
		}

		if (sem_init(&s_raw_read_sems[i], 0, 0) < 0) {
			ERROR("semphare init failed: %s", strerror(errno));
			goto failed;
		}

		if (sem_init(&s_raw_write_sems[i], 0, RING_BUF_SIZE) < 0) {
			ERROR("semphare init failed: %s", strerror(errno));
			goto failed;
		}
	}

	return 0;

failed:
	ipc_destroy(s_tunnel_manage.recv);
	tun_finit(s_tunnel_manage.raw_fd);

	for (int i = 0; i < nraw; i++) {
		ring_buf_destroy(s_raw_bufs[i]);

		if (s_raw_threads[i])
			pthread_cancel(s_raw_threads[i]);

		sem_destroy(&s_raw_read_sems[i]);
		sem_destroy(&s_raw_write_sems[i]);
	}

	return -1;
}
