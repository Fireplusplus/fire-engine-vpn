#ifndef __IPC_20200131__
#define __IPC_20200131__

#include <sys/types.h>
#include <sys/socket.h>

typedef struct ipc_st ipc_st;

/*
 * @brief 创建ipc监听者
 * @param[in] domain AF_UNIX: 本地通信, AF_INET: 跨主机通信
 * @param[in] addr 监听者的地址: 本地路径|ip
 * @param[in] port domain==AF_INET时为监听端口
 * @return 失败返回NULL
 */
struct ipc_st * ipc_listener_create(int domain, const char *addr, short port);

/*
 * @brief 接收客户端连接
 * @param[in] ipc_listener返回的ipc_st
 * @return 失败返回NULL, 成功返回接收的ipc_st
 */
struct ipc_st * ipc_accept(struct ipc_st *ipc);

/*
 * @brief 创建ipc客户端
 * @param[in] domain AF_UNIX: 本地通信, AF_INET: 跨主机通信
 * @param[in] addr 服务端监听地址: 路径|ip
 * @param[in] port domain==AF_INET时为服务端监听端口
 * @return 失败返回NULL, 成功返回ipc_st
 */
struct ipc_st * ipc_client_create(int domain, const char *addr, short port);

/*
 * @brief 销毁ipc资源
 * @param[in] ipc ipc_xxx_create返回的指针
 * @return 无
 */
void ipc_destroy(struct ipc_st *ipc);

/*
 * @brief ipc接收数据
 * @param[out] buf 输出缓冲区
 * @param[in] size 输出缓冲区大小
 * @return <0: 失败 >0: 接收数据的大小
 */
int ipc_recv(struct ipc_st *ipc, void *buf, uint32_t size);

/*
 * @brief ipc发送数据
 * @param[in] struct ipc_st
 * @param[out] buf 输出缓冲区
 * @param[in] size 输出缓冲区大小
 * @return <0: 失败 >0: 发送数据的大小
 */
int ipc_send(struct ipc_st *ipc, void *buf, uint32_t size);

/*
 * @brief 获取对端地址
 * @param[in] struct ipc_st
 * @param[out] ip ip
 * @param[out] port port
 * @return <0: 失败 >0: 成功
 */
int ipc_peer_addr(struct ipc_st *ipc, uint32_t *ip, short *port);

/*
 * @brief 获取通信句柄
 * @param[in] struct ipc_st
 * @return <0: 失败 >0: fd
 */
int ipc_fd(struct ipc_st *ipc);

#endif
