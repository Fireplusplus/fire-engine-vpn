#include "tun.h"

int main()
{
	int tun_fd = -1;
	char buf[4096] = {0};
	const char * dev = "vpntun";
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
	
	while (1)
	{
		int ret;
		struct tun_pi * pi = NULL;

		ret = read(tun_fd, buf, sizeof(buf)-1);
		if (ret < 0)
		{
			perror("read");
			break;
		}

		buf[ret] = 0;
		pi = (struct tun_pi *)buf;
		if (pi->flags == TUN_PKT_STRIP)
		{
			printf("pkt is broken\n"); 
			printf("proto:%d\n", pi->proto);
			continue;
		}
		printf("proto:%02x\n", ntohs(pi->proto));
	}

	tun_close(tun_fd);

	return 0;
}


