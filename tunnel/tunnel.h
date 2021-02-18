#ifndef __TUNNEL_20210214__
#define __TUNNEL_20210214__

#define EV_THREADS_NUM	3

uint32_t tunnel_ev_rss(int fd, void *arg);

void conn_listen();

int tunnel_init(int server, int nraw);

#endif
