#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include <linux/ip.h>

#include <iostream>
#include <map>

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

struct net_range_st {
	uint32_t start;
	uint32_t end; 
};

struct tunnel_manage_st {
	int server;			/* 是否服务端 */
	int raw_fd;			/* 原始输入句柄 */
	int enc_fd;			/* 加密流句柄 */
	ipc_st *listen;		/* 监听vpn_manage的句柄 */
	ipc_st *recv;		/* 同vpn_manage的通信句柄 */
};

struct tunnel_st {
	uint8_t  bad;
	int fd;								/* 加密流通信句柄 */
	uint32_t seed;						/* 随机种子 */
	struct crypto_st *crypt;			/* 加密器 */
	char user[MAX_USER_LEN];			/* 用户名 */
	uint64_t last_input;				/* 上次输入时间 */
	uint64_t last_output;				/* 上次输出时间 */
	net_range_st* nets[MAX_NETS_CNT];	/* 对端子网 */
};

struct raw_data_st {
	int len;
	uint8_t data[0];
};

struct vpn_head_st {
	uint16_t old_len;
	uint16_t data_len;
	uint32_t reserve;
	uint8_t data[0];
} VPN_PACKED;

/*

route tree

0.0.0.0~255.255.255.255

0.0.0.0~126.255.255.255	 127.0.0.1~255.255.255.255

0.0.0.0~63.255.255.255.255 64.0.0.1~126.255.255.255  127.0.0.1~191.255.255.255 192.0.0.0~255.255.255.255

*/

bool range_comp(net_range_st *lhs, net_range_st *rhs)
{
	char buf[20], buf2[20], buf3[20], buf4[20];

	if (lhs->start < rhs->start && lhs->end < rhs->end) {
		DEBUG("true: lhs: %s~%s, rhs: %s~%s", 
			ip2str(lhs->start, buf, 20),
			ip2str(lhs->end, buf2, 20),
			ip2str(rhs->start, buf3, 20),
			ip2str(rhs->end, buf4, 20));
		return true;
	}
	
	DEBUG("false: lhs: %s~%s, rhs: %s~%s", 
			ip2str(lhs->start, buf, 20),
			ip2str(lhs->end, buf2, 20),
			ip2str(rhs->start, buf3, 20),
			ip2str(rhs->end, buf4, 20));
	return false;
}

typedef bool (*net_comp)(net_range_st *, net_range_st *);


#define RING_BUF_SIZE		1024
#define RAW_THREAD_MAX		8
#define TUNNEL_TIMEOUT		10

static struct tunnel_manage_st s_tunnel_manage;					/* 全局管理信息 */
static map<net_range_st *, tunnel_st *, net_comp> s_tunnel_list(range_comp);	/* 隧道信息缓存表 */
static struct ring_buf_st * s_raw_bufs[RAW_THREAD_MAX];			/* 内网数据包缓冲区 */
static pthread_t s_raw_threads[RAW_THREAD_MAX];					/* 内网数据处理线程 */
static sem_t s_raw_read_sems[RAW_THREAD_MAX];					/* 内网数据包缓冲可读信号量 */
static sem_t s_raw_write_sems[RAW_THREAD_MAX];					/* 内网数据包缓冲可写信号量 */
static int s_raw_num = RAW_THREAD_MAX;							/* raw个数 */

#define RAW_IDX_BY_TUNNEL(tl)	(((uint32_t)tl->seed) % s_raw_num)

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
	crypto_destroy(tl->crypt);
	
	if (tl->fd)
		close(tl->fd);
	
	free(tl);
}

static net_range_st * net_range_create(net_st *net)
{
	assert(net);
	
	net_range_st *nr = (net_range_st *)calloc(1, sizeof(net_range_st));
	if (!nr)
		return NULL;
	
	//127.1.0.0/255.255.0.0 ==> 127.1.0.0~127.1.255.255
	nr->start = net->ip & net->mask;
	nr->end = nr->start | (~(net->mask));

	return nr;
}

static tunnel_st * tunnel_create(int fd, uint8_t *buf, int size)
{
	struct cmd_tunnel_st *cmd = (struct cmd_tunnel_st *)buf;
	if (!buf || size != (int)(cmd->klen + sizeof(struct cmd_tunnel_st))) {
		DEBUG("invalid tunnel cmd size: %d, expect: %lu", size, cmd->klen + sizeof(struct cmd_tunnel_st));
		return NULL;
	}

	int i;
	tunnel_st *tl = (tunnel_st*)calloc(1, sizeof(tunnel_st));
	if (!tl)
		return NULL;
	
	memcpy(tl->user, cmd->user, sizeof(tl->user));
	tl->last_input = cur_time();
	tl->last_output = tl->last_input;
	tl->fd = fd;
	tl->seed = cmd->seed;
	tl->crypt = crypto_create(cmd->pubkey, cmd->klen);
	if (!tl->crypt)
		goto failed;
	
	if (ev_register(fd, enc_input, tl) < 0)
		goto failed;
	
	for (i = 0; i < (int)(sizeof(cmd->nets) / sizeof(cmd->nets[0])) && i < MAX_NETS_CNT; i++) {
		struct net_st *net = &(cmd->nets[i]);
		if (!net->ip || !net->mask)
			break;
		
		net_range_st *nr = net_range_create(net);
		if (!nr) {
			/* 定期根据活跃时间删除无效的隧道, 此处失败不用管了 */
			goto failed;
		}

		char buf[20], buf2[20];
		DEBUG("true: add range: %s~%s", 
			ip2str(nr->start, buf, 20),
			ip2str(nr->end, buf2, 20));
		
		tl->nets[i] = nr;
		s_tunnel_list[nr] = tl;
	}
	
	INFO("conn(%s) fd(%d) established success", tl->user, tl->fd);
	return tl;

failed:
	if (i <= 0)
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
static struct tunnel_st * select_tunnel_by_rawpkt(struct raw_data_st *pkt)
{
	if (s_tunnel_list.empty())
		return NULL;
	
	struct iphdr *iph = (struct iphdr *)pkt->data;

	char sip[16], dip[16];
	DEBUG("ip head len: %u, saddr: %s, daddr: %s", iph->ihl << 2, 
				ip2str(iph->saddr, sip, sizeof(sip)),
				ip2str(iph->daddr, dip, sizeof(dip)));
	
	struct net_range_st nr = {iph->daddr, iph->daddr};
	map<net_range_st *, tunnel_st *, net_comp>::iterator it;
	it = s_tunnel_list.find(&nr);
	if (it == s_tunnel_list.end()) {
		return NULL;
	}

	//DUMP_HEX("raw pkt", pkt->data, pkt->len);
	return it->second;
}

/* 处理原始输入: 识别隧道, buf分发 */
static void raw_input(int fd, short event, void *arg)
{
	struct raw_data_st *pkt = (struct raw_data_st *)malloc(PKT_SIZE + sizeof(struct raw_data_st));
	if (!pkt) {
		DEBUG("raw input no memory");
		return;
	}

	pkt->len = read(fd, &pkt->data, PKT_SIZE);
	if (pkt->len <= 0) {
		DEBUG("raw read failed: %s", strerror(errno));
		free(pkt);
		return; 
	}

	DEBUG("raw input len: %d", pkt->len);

	struct tunnel_st *tl = select_tunnel_by_rawpkt(pkt);
	if (!tl) {
		DEBUG("drop raw: not find tunnel");
		free(pkt);
		return;
	}

	int idx = RAW_IDX_BY_TUNNEL(tl);
	struct ring_buf_st *rb = s_raw_bufs[idx];
	DEBUG("pkt enqueue: idx: %d", idx);

	RAW_WAIT_WRITE_IDX(idx);
	if (!enqueue(rb, pkt)) {
		DEBUG("drop raw: no ring cache");
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

	DEBUG("raw output a pkt");
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

	struct tunnel_st *tl = (struct tunnel_st *)arg;
	tl->last_input = cur_time();

	struct vpn_head_st *head = (struct vpn_head_st *)buf;
	if (ret != (int)head->data_len + (int)sizeof(*head)) {
		DEBUG("drop enc invalid size: ret: %d, expect: %d", ret, (int)head->data_len + (int)sizeof(*head));
		return;
	}

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
	uint8_t buf[PKT_SIZE + sizeof(struct vpn_head_st)];
	uint32_t size = sizeof(buf) - sizeof(struct vpn_head_st);

	struct vpn_head_st *head = (struct vpn_head_st *)buf;

	head->old_len = pkt->len;
	if (crypto_encrypt(tl->crypt, pkt->data, head->old_len,
					head->data, &size) < 0) {
		DEBUG("drop enc failed");
		return -1;
	}

	head->data_len = size;
	head->reserve = 0;

	tl->last_output = cur_time();
	
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

		struct tunnel_st *tl = select_tunnel_by_rawpkt(pkt);
		if (!tl) {
			DEBUG("drop raw: no find tunnel");
			free(pkt);
			continue;
		}

		if (enc_output(tl, pkt) < 0) {
			DEBUG("drop raw: output failed");
			free(pkt);
			continue;
		}
	}
}

static void reset_manage_handle_block()
{
	ipc_destroy(s_tunnel_manage.recv);
	s_tunnel_manage.recv = NULL;

	do {
		s_tunnel_manage.recv = ipc_accept(s_tunnel_manage.listen);
		sleep(1);
	} while (!s_tunnel_manage.recv);
}

/* 接收vpn_managle发送的socket描述符, 建立隧道 */
void conn_listen()
{
	uint8_t buf[BUF_SIZE];
	int new_fd;
	
	while (1) {
		int size = sizeof(buf) / sizeof(buf[0]);
		int vpn_fd = ipc_fd(s_tunnel_manage.recv);

		int ret = recv_fd(vpn_fd, &new_fd, buf, &size);
		if (ret < 0) {
			continue;
		} else if (!ret) {
			reset_manage_handle_block();
			continue;
		}

		(void)tunnel_create(new_fd, buf, size);
	}
}

int tunnel_clean_one(uint64_t now)
{
	tunnel_st *tl = NULL;
	uint8_t end = 1;

	for (auto it = s_tunnel_list.begin(); it != s_tunnel_list.end(); ++it) {
		if (now > it->second->last_input + TUNNEL_TIMEOUT) {
			tl = it->second;

			for (int i = 0; i < MAX_NETS_CNT && tl->nets[i]; i++) {
				net_range_st *tmp = tl->nets[i];
				s_tunnel_list.erase(tmp);
				free(tmp);
			}

			DEBUG("destroy timeout tunnel: %s", tl->user);
			tunnel_destroy(tl);

			end = 0;
			break;
		}
	}

	return end;
}

void tunnel_clean_timer(void *arg)
{
	uint64_t now = cur_time();

	while (tunnel_clean_one(now) == 0);

	ev_timer(TUNNEL_TIMEOUT, tunnel_clean_timer, NULL);
}

int tunnel_init(int server, int nraw)
{
	const char *addr = get_tunnel_addr(server);
	remove(addr);

	s_tunnel_manage.listen = ipc_listener_create(AF_UNIX, addr, 0);
	if (!s_tunnel_manage.listen)
		return -1;

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

	s_raw_num = nraw;

	INFO("create tun: ip: %s", get_tun_ip());
	s_tunnel_manage.raw_fd = tun_init(get_tun_ip());
	if (s_tunnel_manage.raw_fd < 0) {
		ipc_destroy(s_tunnel_manage.recv);
		goto failed;
	}

	/* 监听内网输入数据包, 要放在信号量初始化之后 */
	if (ev_register(s_tunnel_manage.raw_fd, raw_input, NULL) < 0) {
		ERROR("register raw input event failed");
		goto failed;
	}

	if (ev_timer(TUNNEL_TIMEOUT, tunnel_clean_timer, NULL) < 0)
		goto failed;

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
