#ifndef __FD_SEND_20210216__
#define __FD_SEND_20210216__

#include <stdint.h>

/*
 * @brief 发送文件描述符
 * @param[in] fd 发送句柄
 * @param[in] fd_send 待发送的文件描述符
 * @param[in] data 附带传输的数据
 * @param[in] len 附带传输数据的字节数
 * @return <0: 失败 0: 成功
 */
int send_fd(int fd, int fd_send, uint8_t *data, int len);

/*
 * @brief 接收文件描述符
 * @param[in] fd 接收句柄
 * @param[out] fd_recv 接收的文件描述符
 * @param[out] data 附带传输的数据
 * @param[out] len 附带传输数据的字节数
 * @return <0: 失败 0: 成功
 */
int recv_fd(int fd, int *fd_recv, uint8_t *out, int *osize);

#endif