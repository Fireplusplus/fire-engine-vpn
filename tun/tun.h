#pragma once

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

int tun_open(const char * dev);
int tun_setup(const char * dev, struct sockaddr_in * addr);
int tun_close(int fd);
