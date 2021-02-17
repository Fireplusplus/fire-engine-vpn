#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "log.h"

struct ipc_st {
	int fd;								/* 通信句柄 */
	int domain;							/* 协议domain: AF_UNIX | AF_INET */
	union {								/* 地址 */
		struct sockaddr		addr;
		struct sockaddr_un	addr_un;
		struct sockaddr_in	addr_in;
	};
	int addr_size;						/* sockaddr的字节数 */
};

static struct ipc_st * ipc_create()
{
	return (struct ipc_st *)calloc(1, sizeof(struct ipc_st));
}

/*
 * @brief 销毁ipc资源
 * @param[in] ipc ipc_xxx_create返回的指针
 * @return 无
 */
void ipc_destroy(struct ipc_st *ipc)
{
	if (!ipc)
		return;
	
	if (ipc->fd >= 0)
		close(ipc->fd);
	if (ipc->domain == AF_UNIX && ipc->addr_un.sun_path[0] != '\0') {
		remove(ipc->addr_un.sun_path);
	}
	
	free(ipc);
}

static int set_unblock(int fd)
{
	int flags;
	if ((flags = fcntl(fd, F_GETFL, NULL)) < 0) {
		DEBUG("fcntl failed: %s", strerror(errno));
		return -1;
	}
	
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		DEBUG("fcntl failed: %s", strerror(errno));
		return -1;
	}
	
	return 0;
}

/*
 * @brief 创建ipc监听者
 * @param[in] domain AF_UNIX: 本地通信, AF_INET: 跨主机通信
 * @param[in] addr 监听者的地址: 本地路径|ip
 * @param[in] port domain==AF_INET时为监听端口
 * @return 失败返回NULL
 */
struct ipc_st * ipc_listener_create(int domain, const char *addr, short port)
{
	if ((domain != AF_UNIX && domain != AF_INET) || !addr)
		return NULL;

	struct ipc_st *ipc = ipc_create();
	if (!ipc)
		return NULL;
	
	ipc->domain = domain;
	ipc->fd = socket(domain, SOCK_STREAM, 0);
	if (ipc->fd < 0) {
		DEBUG("socket error: %s", strerror(errno));
		ipc_destroy(ipc);
		return nullptr;
	}

	if (domain == AF_UNIX) {
		struct sockaddr_un *local = &ipc->addr_un;

		local->sun_family = AF_UNIX;
		snprintf(local->sun_path, sizeof(local->sun_path), addr),
		ipc->addr_size = sizeof(struct sockaddr_un);
	} else {
		struct sockaddr_in *local = &ipc->addr_in;

		local->sin_family = AF_INET;
		local->sin_port = htons(port);
		inet_pton(AF_INET, addr, &(local->sin_addr.s_addr));
		ipc->addr_size = sizeof(struct sockaddr_in);

		int flag = 1, len = sizeof(int);
		if( setsockopt(ipc->fd, SOL_SOCKET, SO_REUSEADDR, &flag, len) == -1) {
			DEBUG("set reuseaddr failed: %s", strerror(errno));
		}
	}
	
	if (bind(ipc->fd, &ipc->addr, ipc->addr_size) < 0) {
		DEBUG("bind %s:%d failed: %s", addr, port, strerror(errno));
		goto failed;
	}
	
	if (listen(ipc->fd, 10) < 0) {
		DEBUG("listen error: %s", strerror(errno));
		goto failed;
	}

	DEBUG("server listen on: %s:%d", addr, port);

	(void)set_unblock(ipc->fd);
	return ipc;

failed:
	ipc_destroy(ipc);
	return NULL;
}

/*
 * @brief 接收客户端连接
 * @param[in] ipc_listener返回的ipc_st
 * @return 失败返回NULL, 成功返回接收的ipc_st
 */
struct ipc_st * ipc_accept(struct ipc_st *ipc)
{
	if (!ipc)
		return NULL;
	
	struct ipc_st *newipc = ipc_create();
	if (!newipc)
		return NULL;
	
	newipc->domain = ipc->domain;
	if (ipc->domain == AF_UNIX) {
		newipc->addr_size = sizeof(struct sockaddr_un);
		newipc->fd = accept4(ipc->fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	} else {
		newipc->addr_size = sizeof(struct sockaddr_in);
		newipc->fd = accept4(ipc->fd, &newipc->addr, 
			(socklen_t*)&newipc->addr_size, SOCK_NONBLOCK | SOCK_CLOEXEC);
	}

	if (newipc->fd < 0) {
		DEBUG("accept4 error: %s", strerror(errno));
		ipc_destroy(newipc);
		return NULL;
	}

	DEBUG("accept a client: newfd(%d)\n", newipc->fd);
	return newipc;
}

/*
 * @brief 创建ipc客户端
 * @param[in] domain AF_UNIX: 本地通信, AF_INET: 跨主机通信
 * @param[in] addr 服务端监听地址: 路径|ip
 * @param[in] port domain==AF_INET时为服务端监听端口
 * @return 失败返回NULL, 成功返回ipc_st
 */
struct ipc_st * ipc_client_create(int domain, const char *addr, short port)
{
	if ((domain != AF_UNIX && domain != AF_INET) || !addr)
		return NULL;
	
	struct ipc_st *ipc = ipc_create();
	if (!ipc)
		return NULL;
	
	ipc->domain = domain;
	ipc->fd = socket(domain, SOCK_STREAM, 0);
	if (ipc->fd < 0) {
		DEBUG("socket error: %s", strerror(errno));
		ipc_destroy(ipc);
		return NULL;
	}

	if (domain == AF_UNIX) {
		struct sockaddr_un *local = &ipc->addr_un;
		memset(local, 0, sizeof(*local));
		local->sun_family = AF_UNIX;
		
		if (bind(ipc->fd, &ipc->addr, sizeof(struct sockaddr_un)) < 0) {
			DEBUG("bind %s:%d failed: %s", addr, port, strerror(errno));
			goto failed;
		}
	}
	
	char buf[108];
	int size;
	if (domain == AF_UNIX) {
		struct sockaddr_un *peer = (struct sockaddr_un *)buf;
		size = sizeof(*peer);

		peer->sun_family = AF_UNIX;
		snprintf(peer->sun_path, sizeof(peer->sun_path), addr);
	} else {
		struct sockaddr_in *peer = (struct sockaddr_in *)buf;
		size = sizeof(*peer);

		peer->sin_family = AF_INET;
		peer->sin_port = htons(port);
		inet_pton(AF_INET, addr, &(peer->sin_addr.s_addr));
	}
	
	if (connect(ipc->fd, (struct sockaddr*)buf, size) < 0) {
		DEBUG("connect error: %s", strerror(errno));
		goto failed;
	}
	
	set_unblock(ipc->fd);
	return ipc;

failed:
	ipc_destroy(ipc);
	return NULL;
}

/*
 * @brief ipc接收数据
 * @param[in] struct ipc_st
 * @param[out] buf 输出缓冲区
 * @param[in] size 输出缓冲区大小
 * @return <=0: 失败 >0: 接收数据的大小
 */
int ipc_recv(struct ipc_st *ipc, void *buf, uint32_t size)
{
	if (!ipc)
		return -1;
	
	int len = read(ipc->fd, buf, size);
	if (len <= 0) {
		DEBUG("read error(len: %d): %s", len, strerror(errno));
	}
	
	return len;
}

/*
 * @brief ipc发送数据
 * @param[in] struct ipc_st
 * @param[out] buf 输出缓冲区
 * @param[in] size 输出缓冲区大小
 * @return <0: 失败 >0: 发送数据的大小
 */
int ipc_send(struct ipc_st *ipc, void *buf, uint32_t size)
{
	if (!ipc)
		return -1;
	
	int ret = write(ipc->fd, buf, size);
	if (ret <= 0) {
		DEBUG("write error: %s", strerror(errno));
		return ret;
	}

	return ret;
}

/*
 * @brief 获取对端地址
 * @param[in] struct ipc_st
 * @param[out] ip ip
 * @param[out] port port
 * @return <0: 失败 >0: 成功
 */
int ipc_peer_addr(struct ipc_st *ipc, uint32_t *ip, short *port)
{
	struct sockaddr_in peer;
	socklen_t len = sizeof(peer);

	if (!ipc)
		return -1;

	if (getpeername(ipc->fd, (struct sockaddr *)&peer, &len) < 0) {
		DEBUG("getpeername error: %s", strerror(errno));
		return -1;
	}
	
	*ip = peer.sin_addr.s_addr;
	*port = peer.sin_port;
	
	return 0;
}

/*
 * @brief 获取通信句柄
 * @param[in] struct ipc_st
 * @return <0: 失败 >0: fd
 */
int ipc_fd(struct ipc_st *ipc)
{
	return ipc ? ipc->fd : -1;
}
