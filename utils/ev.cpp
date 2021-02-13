#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <iostream>
#include <unordered_map>

#include "log.h"
#include "mem.h"
#include "ev.h"

using namespace std;

struct event_action_st {
	int (*create)();
	void (*destroy)(int);
	void (*on_do)(int, short, void *);
	const char *desc;
};

static unordered_map<int, struct event *> s_ev_list;		/* 事件缓存表 */
struct event_base *s_ev_base;


int ev_register(int ipc, event_callback_fn fn, void *arg)
{
	if (ipc < 0 || !fn)
		return -1;
	
	if (s_ev_list.find(ipc) != s_ev_list.end())
		return 0;

	struct event *ev = event_new(s_ev_base, ipc, EV_READ | EV_PERSIST, fn, arg);
	if (!ev) {
		DEBUG("create event failed");
		return -1;
	}

	event_add(ev, NULL);

	s_ev_list[ipc] = ev;
	return 0;
}

void ev_unregister(int ipc)
{
	if (ipc < 0)
		return;
	
	unordered_map<int, struct event *>::iterator it = s_ev_list.find(ipc);
	if (it == s_ev_list.end()) {
		DEBUG("not find event, destroy failed !");
		return;
	}

	event_del(it->second);
	event_free(it->second);

	s_ev_list.erase(it);
}

/* 服务启动运行：循环事件 */
void ev_run()
{
	event_base_dispatch(s_ev_base);
}

/* 初始化服务环境 */
int ev_init()
{
	s_ev_base = event_base_new();
	if (!s_ev_base) {
		ERROR("event_init event_base_new failed\n");
		return -1;
	}

	return 0;
}
