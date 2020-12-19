#ifndef EVENT_20201213
#define EVENT_20201213

/* 服务启动运行：循环事件 */
void event_run();

/* 初始化服务环境 */
int event_init(int server);

/* 注册新事件 */
int event_register(int fd, void (*on_do)(int, short, void *), void *user_data);

#endif
