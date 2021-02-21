#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "local_config.h"

struct server_conf {
	short port_listen;
	char *ip_listen;
};

static struct server_conf s_server_conf = {6666, (char *)"172.18.39.249"};
static struct server_conf s_client_conf = {0, (char *)"172.18.39.251"};

short get_client_port()
{
	return s_client_conf.port_listen;
}

const char * get_client_ip()
{
	return s_client_conf.ip_listen;
}

short get_server_port()
{
	return s_server_conf.port_listen;
}

const char * get_server_ip()
{
	return s_server_conf.ip_listen;
}

const char * get_branch_user()
{
	return "test";
}

const char * get_branch_pwd()
{
	return "testpwd";
}

#define TUNNEL_ADDR	"/tmp/tunnel"
#define TUNNEL_ADDR_SERVER TUNNEL_ADDR"_s"		/* 区分客户端服务器的地址, 方便一台机器调试 */
#define TUNNEL_ADDR_CLIENT TUNNEL_ADDR"_c"

const char * get_tunnel_addr(int server)
{
	return server ? TUNNEL_ADDR_SERVER : TUNNEL_ADDR_CLIENT;
}

static char *s_tun_ip;
const char * get_tun_ip()
{
	if (s_tun_ip)
		return s_tun_ip;
	
	const char *addr = "/sys/class/net/eth0/address";
	FILE *fp = fopen(addr, "r");
	if (!fp)
		return NULL;
	
	int buf[5] = {0};
	int ret = fread(buf, 1, sizeof(buf) - 1, fp);
	fclose(fp);
	if (ret <= 0) {
		return NULL;
	}

	for (int i = 1; i < (int)(sizeof(buf) / sizeof(buf[0])); i++)
		buf[0] += buf[i];

	int len = strlen("xxx.xxx.xxx.xxx") + 1;
	s_tun_ip = (char *)calloc(1, len);
	if (!s_tun_ip)
		return NULL;
	
	inet_ntop(AF_INET, &buf[0], s_tun_ip, len);
	return s_tun_ip;
}