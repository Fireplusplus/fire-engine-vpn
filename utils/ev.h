#ifndef __EV_20210213__
#define __EV_20210213__


typedef void (*ev_callback)(int, short, void *);
typedef uint32_t (*ev_rss)(int fd, void *arg);

/*
 * @brief 定时事件
 * @param[in] timeout 定时时间(s)
 * @param[in] fn 定时事件回调
 * @param[in] arg fn的第三个参数
 * @return <0: 失败 0: 成功
 */
int ev_timer(int timeout, ev_callback fn, void *arg);

/*
 * @brief 注册事件
 * @param[in] fd 文件描述符
 * @param[in] fn 读事件回调
 * @param[in] arg fn的第三个参数
 * @return <0: 失败 0: 成功
 */
int ev_register(int fd, ev_callback fn, void *arg);

/*
 * @brief 注销事件
 * @param[in] fd 文件描述符
 * @return 无
 */
int ev_unregister(int fd);

/*
 * @brief 外部主动事件分发
 * @return 无
 */
void ev_run();

/*
 * @brief 初始化event环境
 * @param[in] nzone 划分的区域数: <= 0: 不划分区域，外部分发 >0: 内部划分nzone区域并用nzone个线程分发
 * @param[in] fn 分发函数
 * @return <0: 失败 0: 成功
 */
int ev_init(int nzone, ev_rss fn);

#endif
