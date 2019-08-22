#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

int tun_open(const char * dev)
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
    ifr.ifr_flags |= IFF_TAP;       /* 以太网设备 */

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)
    {
        close(fd);
        return -2;
    }

    /* 进程退出依旧保留网卡 */
    if(ioctl(fd, TUNSETPERSIST, 1) < 0) {
        printf("remain tun fail\n");
    }

    if (strcmp(ifr.ifr_name, dev) != 0)
        printf("tun name: %s\n", ifr.ifr_name);
    return fd;
}

int tun_setup(const char * dev, struct sockaddr_in * addr)
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
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        printf("set interface up fail\n");
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

    return 0;

err:
    close(fd);
    return -1;
}

int tun_close(int fd)
{
    close(fd);
}

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


