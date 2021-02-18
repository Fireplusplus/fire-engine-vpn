#ifndef TUN_20201215
#define TUN_20201215

#include <linux/if.h>
#include <linux/if_tun.h>

int tun_init();
void tun_finit(int fd);

#endif