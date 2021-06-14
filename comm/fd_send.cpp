#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "fd_send.h"
#include "log.h"

#define CONTROLLEN CMSG_LEN(sizeof(int))	/* 一个文件描述符的长度 */

/*
 * @brief 发送文件描述符
 * @param[in] fd 发送句柄
 * @param[in] fd_send 待发送的文件描述符
 * @param[in] data 附带传输的数据
 * @param[in] len 附带传输数据的字节数
 * @return <0: 失败 0: 成功
 */
int send_fd(int fd, int fd_send, uint8_t *data, int len)
{
	if (fd < 0 || len < 0) {
		DEBUG("invalid param: fd: %d, fd_send: %d, len: %d", fd, fd_send, len);
		return -1;
	}

	if ((data && !len) || (!data && len)) {
		data = NULL;
		len = 0;
	}

	struct iovec iov[1] = {{data, (size_t)len}};
	uint8_t buf[1024] = {0};
	struct cmsghdr *cmsg = (struct cmsghdr *)buf;
	struct msghdr msg;

	memset(&msg, 0, sizeof(msg));
	cmsg->cmsg_level = SOL_SOCKET;

	msg.msg_iov = iov;
	msg.msg_iovlen  = sizeof(iov) / sizeof(iov[0]);

	if (fd_send < 0) {
		DEBUG("send without fd: iov: data: %p, len: %d", 
				msg.msg_iov->iov_base, (int)msg.msg_iov->iov_len);
	} else {
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CONTROLLEN;

		msg.msg_control = cmsg;
		msg.msg_controllen = CONTROLLEN;

		*(int*)CMSG_DATA(cmsg) = fd_send;

		DEBUG("send with fd(%d): iov: data: %p, len: %d", fd_send, 
				msg.msg_iov->iov_base, (int)msg.msg_iov->iov_len);
	}

	if (sendmsg(fd, &msg, 0) <= 0) {
		DEBUG("sendmsg failed: %s", strerror(errno));
		return -1;
	}
	
	return 0;
}

/*
 * @brief 接收文件描述符
 * @param[in] fd 接收句柄
 * @param[out] fd_recv 接收的文件描述符
 * @param[out] data 附带传输的数据
 * @param[out] len 附带传输数据的字节数
 * @return <0: 失败 0: 成功
 */
int recv_fd(int fd, int *fd_recv, uint8_t *out, int *osize)
{
	uint8_t buf[CONTROLLEN];
	struct iovec iov[1] = {out, (size_t)*osize};
	struct cmsghdr *cmsg = (struct cmsghdr *)buf;
	struct msghdr msg;
	
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen  = sizeof(iov) / sizeof(iov[0]);

	msg.msg_control = cmsg;
	msg.msg_controllen = CONTROLLEN;

	int len = recvmsg(fd, &msg, 0);
	if (!len) {
		DEBUG("recvmsg failed: %s", strerror(errno));
		return 0;
	}

	if(len < 0) {
		if (errno != EAGAIN) {
			DEBUG("recvmsg failed: %s", strerror(errno));
			return 0;
		}

		return -1;
	}

	if(msg.msg_controllen == CONTROLLEN) {
		DEBUG("recv with fd(%d)", *fd_recv);
		*fd_recv = *(int*)CMSG_DATA(cmsg);
	} else {
		DEBUG("recv without fd");
		*fd_recv = -1;
	}
	
	*osize = len;
	return 1;
}