#ifndef __EV_20210213__
#define __EV_20210213__

#include <event2/event.h>

int ev_register(int ipc, event_callback_fn fn, void *arg);

void ev_unregister(int ipc);

/* 服务启动运行：循环事件 */
void ev_run();

/* 初始化服务环境 */
int ev_init();

#endif
