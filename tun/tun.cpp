#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "tun.h"

static int tun_open(const char * dev)
{
	struct ifreq ifr;
	int fd;

	assert(dev != NULL);

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	if (*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	//ifr.ifr_flags |= IFF_TAP;	   /* 以太网设备 */
	ifr.ifr_flags |= IFF_TUN;		/* 点对点设备 */

	if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)
	{
		close(fd);
		return -2;
	}

	/* 进程退出依旧保留网卡 1 */
	if(ioctl(fd, TUNSETPERSIST, 1) < 0) {
		printf("remain tun fail\n");
	}

	if (strcmp(ifr.ifr_name, dev) != 0)
		printf("tun name: %s\n", ifr.ifr_name);
	return fd;
}

static int tun_setup(const char * dev, struct sockaddr_in * addr)
{
	struct ifreq ifr;
	int fd;

	if (NULL == dev || NULL == addr)
		return -1;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		goto err;
	}
	
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	/* get flag */
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		printf("get flag fail\n");
		goto err;
	}
	/* set the interface up */
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		printf("set interface up fail\n");
		goto err;
	}
	/* 混杂模式 */
	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		printf("set promisc\n");
		goto err;
	}
	/* set ip */
	memcpy(&ifr.ifr_addr, addr, sizeof(struct sockaddr));
	if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
		printf("set ip fail\n");
		goto err;
	}
	/* set mask */
	inet_pton(AF_INET, "255.255.255.255", &addr->sin_addr.s_addr);
	memcpy(&ifr.ifr_netmask, addr, sizeof(struct sockaddr));
	if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0) {
		printf("set mask fail\n");
		goto err;
	}

	close(fd);
	return 0;

err:
	close(fd);
	return -1;
}

static void tun_close(int fd)
{
	close(fd);
}

int tun_init()
{
	int tun_fd = -1;
	const char * dev = "tun";
	struct sockaddr_in addr;

	tun_fd = tun_open(dev);
	if (tun_fd < 0)
	{
		printf("create tun fail\n");
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, "13.254.254.131", &addr.sin_addr.s_addr);
	if (tun_setup(dev, &addr) < 0)
		return -2;
	
	return tun_fd;
}

void tun_finit(int fd)
{
	if (fd > 0)
		tun_close(fd);
}
