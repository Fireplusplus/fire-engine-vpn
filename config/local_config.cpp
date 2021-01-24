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
