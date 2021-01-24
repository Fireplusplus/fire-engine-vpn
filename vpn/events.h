#ifndef __EVENT_20201213__
#define __EVENT_20201213__

struct ser_cli_node {
	int sock;
	struct event *ev;
	struct dh_group_st *dh;
	struct crypto_st *crypt;
	
	uint8_t server:1;
};

/* 服务启动运行：循环事件 */
void event_run();

/* 初始化服务环境 */
int event_init(int server);

/* 注册新事件 */
int event_register(int fd, void (*on_do)(int, short, void *), void *user_data);

#endif
