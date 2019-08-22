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

int tun_create(const char * dev)
{
    struct ifreq ifr;
    int fd, err;

    assert(dev != NULL);

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        perror("open");
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    strcpy(ifr.ifr_name, dev);
    ifr.ifr_flags |= IFF_TAP;       /* 以太网设备 */

    err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (err < 0)
    {
        close(fd);
        return -2;
    }

    if (strcmp(ifr_ifr_name, dev) != 0)
        printf("%s\n", ifr.ifr_name);
    return fd;
}

int tun_setup(const char * dev, )
{
    
}

int tun_close(int fd)
{
    close(fd);
}

int main()
{
    int tun_fd = -1;
    char buf[4096] = {0};


    tun_fd = tun_create("vpntun", "13.254.254.131");
    if (tun_fd < 0)
    {
        printf("create tun fail\n");
        return -1;
    }

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

    close(tun_fd);

    return 0;
}


