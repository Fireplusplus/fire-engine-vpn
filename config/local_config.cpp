#include "local_config.h"

struct server_conf {
	short port_listen;
	char *ip_listen;
};

static struct server_conf s_server_conf = {6666, (char *)"127.0.0.1"};

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
