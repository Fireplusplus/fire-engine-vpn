#ifndef __IPC_20200131__
#define __IPC_20200131__

/*
 * @brief 创建ipc监听者
 * @param[in] domain AF_UNIX: 本地通信, AF_INET: 跨主机通信
 * @param[in] addr 监听者的地址: 本地路径|ip
 * @param[in] port domain==AF_INET时为监听端口
 * @return <0: 失败 >=0: 文件描述符
 */
int ipc_listener_create(int domain, const char *addr, short port);

/*
 * @brief 接收客户端连接
 * @param[in] domain AF_UNIX: 本地通信, AF_INET: 跨主机通信
 * @param[in] fd ipc_listener_create返回的描述符
 * @return <0: 失败 >=0: 文件描述符
 */
int ipc_accept(int domain, int fd);

/*
 * @brief 创建ipc客户端
 * @param[in] domain AF_UNIX: 本地通信, AF_INET: 跨主机通信
 * @param[in] addr 服务端监听地址: 路径|ip
 * @param[in] port domain==AF_INET时为服务端监听端口
 * @return <0: 失败 >=0: 文件描述符
 */
int ipc_client_create(int domain, const char *addr, short port);

/*
 * @brief 销毁ipc资源
 * @param[in] fd ipc_xxx_create返回的文件描述符
 * @return 无
 */
void ipc_destroy(int fd);

/*
 * @brief ipc接收数据
 * @param[out] buf 输出缓冲区
 * @param[in] size 输出缓冲区大小
 * @return <0: 失败 >0: 接收数据的大小
 */
int ipc_recv(int fd, void *buf, uint32_t size);

/*
 * @brief ipc发送数据
 * @param[out] buf 输出缓冲区
 * @param[in] size 输出缓冲区大小
 * @return <0: 失败 >0: 发送数据的大小
 */
int ipc_send(int fd, void *buf, uint32_t size);

#endif
