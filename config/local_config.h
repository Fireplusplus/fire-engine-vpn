#ifndef __LOCAL_CONFIG_20201219__
#define __LOCAL_CONFIG_20201219__

short get_server_port();
const char * get_server_ip();

const char * get_branch_user();
const char * get_branch_pwd();
const char * get_tunnel_addr(int server);
#define TUNNEL_PORT 7777

#endif