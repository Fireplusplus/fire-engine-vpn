#ifndef __TUN_20201215__
#define __TUN_20201215__

#include <linux/if.h>
#include <linux/if_tun.h>

int tun_init(const char *tunip);
void tun_finit(int fd);

#endif