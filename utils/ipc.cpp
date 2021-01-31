#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "log.h"


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
 * @return <0: 失败 >=0: 文件描述符
 */
int ipc_listener_create(int domain, const char *addr, short port)
{
	if ((domain != AF_UNIX && domain != AF_INET) || !addr)
		return -1;
	
	int sock = socket(domain, SOCK_STREAM, 0);
	if (sock < 0) {
		DEBUG("socket error: %s", strerror(errno));
		return -1;
	}

	char buf[256] = {0};
	int size = 0;

	if (domain == AF_UNIX) {
		struct sockaddr_un *local = (struct sockaddr_un *)buf;

		local->sun_family = AF_UNIX;
		snprintf(local->sun_path, sizeof(local->sun_path), addr),
		size = sizeof(struct sockaddr_un);
	} else {
		struct sockaddr_in *local = (struct sockaddr_in *)buf;

		local->sin_family = AF_INET;
		local->sin_port = htons(port);
		inet_pton(AF_INET, addr, &(local->sin_addr.s_addr));
		size = sizeof(struct sockaddr_in);

		int flag = 1, len = sizeof(int);
		if( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, len) == -1) {
			DEBUG("set reuseaddr failed: %s", strerror(errno));
		}
	}
	
	if (bind(sock, (struct sockaddr*)buf, size) < 0) {
		DEBUG("bind %s:%d failed: %s", addr, port, strerror(errno));
		goto failed;
	}
	
	if (listen(sock, 10) < 0) {
		ERROR("listen error: %s", strerror(errno));
		goto failed;
	}

	DEBUG("server listen on: %s:%d", addr, port);

	(void)set_unblock(sock);
	return sock;

failed:
	close(sock);
	return -1;
}

/*
 * @brief 销毁监听者
 * @param[in] fd ipc_listener_create返回的描述符
 * @return 无
 */
void ipc_listener_destroy(int fd)
{
	if (fd < 0)
		return;

	close(fd);
}

/*
 * @brief 接收客户端连接
 * @param[in] domain AF_UNIX: 本地通信, AF_INET: 跨主机通信
 * @param[in] fd ipc_listener_create返回的描述符
 * @return <0: 失败 >=0: 文件描述符
 */
int ipc_listen(int domain, int fd)
{
	if ((domain != AF_UNIX && domain != AF_INET) || fd < 0)
		return -1;
	
	int newfd = -1;
	
	if (domain == AF_UNIX) {
		newfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	} else {
		struct sockaddr_in peer;
		socklen_t len = sizeof(peer);

		newfd = accept4(fd, (struct sockaddr*)&peer, &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	}

	if (newfd < 0) {
		DEBUG("accept4 error: %s", strerror(errno));
		return -1;
	}

	DEBUG("accept a client: newfd(%d)\n", newfd);
	return newfd;
}

/*
 * @brief 创建ipc客户端
 * @param[in] domain AF_UNIX: 本地通信, AF_INET: 跨主机通信
 * @param[in] addr 服务端监听地址: 路径|ip
 * @param[in] port domain==AF_INET时为服务端监听端口
 * @return <0: 失败 >=0: 文件描述符
 */
int ipc_client_create(int domain, const char *addr, short port)
{
	if ((domain != AF_UNIX && domain != AF_INET) || !addr)
		return -1;
	
	int sock = socket(domain, SOCK_STREAM, 0);
	if (sock < 0) {
		DEBUG("socket error: %s", strerror(errno));
		return -1;
	}

	char buf[256] = {0};
	int size = 0;

	if (domain == AF_UNIX) {
		struct sockaddr_un local;
		memset(&local, 0, sizeof(local));

		local.sun_family = AF_UNIX;
		
		if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) {
			DEBUG("bind %s:%d failed: %s", addr, port, strerror(errno));
			goto failed;
		}
	}
	
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
	
	if (connect(sock, (struct sockaddr*)buf, size) < 0) {
		DEBUG("connect error: %s", strerror(errno));
		goto failed;
	}
	
	set_unblock(sock);
	return sock;

failed:
	close(sock);
	return -1;
}

/*
 * @brief 销毁ipc客户端
 * @param[in] fd ipc_client_create返回的文件描述符
 * @return 无
 */
void ipc_client_destroy(int fd)
{
	if (fd < 0)
		return;

	char buf[256] = {0};
	socklen_t size = sizeof(buf);

	if (getsockname(fd, (struct sockaddr *)buf, &size) < 0) {
		DEBUG("getsockname error: %s", strerror(errno));
	}

	/* UNIX域套接字还需删除路径标识 */
	struct sockaddr_un *local = (struct sockaddr_un *)buf;
	if (size == sizeof(struct sockaddr_un) && local->sun_family == AF_UNIX) {
		if (local->sun_path[0] != '\0')
			remove(local->sun_path);
	}

	close(fd);
}

/*
 * @brief ipc接收数据
 * @param[out] buf 输出缓冲区
 * @param[in] size 输出缓冲区大小
 * @return <=0: 失败 >0: 接收数据的大小
 */
int ipc_recv(int fd, void *buf, uint32_t size)
{
    int len = read(fd, buf, size);
	if (len <= 0) {
		DEBUG("read error: %s", strerror(errno));
		return len;
	}
	
	return len;
}

/*
 * @brief ipc发送数据
 * @param[out] buf 输出缓冲区
 * @param[in] size 输出缓冲区大小
 * @return <0: 失败 >0: 发送数据的大小
 */
int ipc_send(int fd, void *buf, uint32_t size)
{
	int ret = write(fd, buf, size);
	if (ret <= 0) {
		DEBUG("write error: %s", strerror(errno));
		return ret;
	}

	return ret;
}
