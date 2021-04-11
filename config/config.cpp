#include <iostream>
#include <string>
#include <unordered_map>
#include <iniparser.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

using namespace std;

#include "config.h"
#include "proto.h"
#include "comm.h"
#include "mem.h"

/*
[server]
netcnt = 1
net1 = 1.1.1.0/255.255.255.0

[user1]
name = test
pwd = test
netcnt = 2
net1 = 192.168.100.0/255.255.255.0
net2 = 192.168.200.0/255.255.255.0
*/

#define NET_SIZE_MAX 32

struct server_set_st {
	int nnets;
	struct net_st nets[10];
};

struct user_st {
	string name;
	string pwd;
	int nnets;
	uint8_t data[0];
};

static struct server_set_st s_server_conf;
static unordered_map<string, struct user_st *> s_user_conf;

#define USER_MAX	20000
#define FIRE_PATH	"/etc/fire.ini"

static const char * get_user_str(dictionary *dict, int seq, const char *key)
{
	static char buf[32];
	snprintf(buf, sizeof(buf), "user%d:%s", seq, key);

	return iniparser_getstring(dict, buf, NULL);
}

static int get_user_int(dictionary *dict, int seq, const char *key)
{
	static char buf[32];
	snprintf(buf, sizeof(buf), "user%d:%s", seq, key);

	return iniparser_getint(dict, buf, 0);
}

static int net2ip_mask(const char *net, uint32_t *ip, uint32_t *mask)
{
	static char buf_ip[NET_SIZE_MAX], buf_mask[NET_SIZE_MAX];

	assert(net && ip && mask);
	
	if (strlen(net) >= NET_SIZE_MAX) {
		DEBUG("invalid net length");
		return -1;
	}

	int cnt = sscanf(net, "%[^/]/%[^/]", buf_ip, buf_mask);
	if (cnt != 2) {
		DEBUG("invalid net format");
		return -1;
	}
	
	*ip = str2ip(buf_ip);
	*mask = str2ip(buf_mask);
	
	return 0;
}

const char * get_user_name(const struct user_st *user)
{
	return user ? user->name.c_str() : "";
}

const struct user_st * get_user(const char *name)
{
	if (!name)
		return NULL;
	
	unordered_map<string, struct user_st *>::iterator it = s_user_conf.find(name);
	if (it == s_user_conf.end()) {
		DEBUG("not found user: %s", name);
		return NULL;
	}

	return it->second;
}

int get_user_net(const struct user_st *user, char *buf, int size)
{
	if (!user || !buf || size <= 0)
		return 0;

	int cnt = size / sizeof(struct net_st);
	cnt = cnt < user->nnets ? cnt : user->nnets;

	memcpy(buf, user->data, cnt * sizeof(struct net_st));
	return cnt;
}

int get_server_net(char *buf, int size)
{
	if (!buf || size <= 0)
		return 0;

	int cnt = size / sizeof(struct net_st);
	cnt = cnt < s_server_conf.nnets ? cnt : s_server_conf.nnets;

	memcpy(buf, s_server_conf.nets, cnt * sizeof(struct net_st));
	return cnt;
}

int check_user(const struct user_st *user, const char *pwd)
{
	if (!user || !pwd)
		return -1;
	
	if (user->pwd != pwd) {
		DEBUG("pwd not match: pwd: %s, expected: %s", pwd, user->pwd.c_str());
		return -1;
	}
	
	return 0;
}

static void print_user(struct user_st *user)
{
	assert(user);
	int cnt = user->nnets;

	DEBUG("user: ");
	DEBUG("      name: %s, pwd: %s", user->name.c_str(), user->pwd.c_str());

	struct net_st *nets = (struct net_st*)user->data;
	DEBUG("      nets: %d", cnt);

	char ip_buf[16], mask_buf[16];
	for (int i = 0; i < cnt; i++) {
		DEBUG("            %s/%s", ip2str(nets[i].ip, ip_buf, sizeof(ip_buf)),
							ip2str(nets[i].mask, mask_buf, sizeof(mask_buf)));
	}
}

static void load_user_conf(dictionary *dict)
{
	int i = 1;
	char buf[20];
	
	do {
		const char *name = get_user_str(dict, i, "name");
		if (!name)
			break;
		
		const char *pwd = get_user_str(dict, i, "pwd");
		if (!pwd)
			break;
		
		int cnt = get_user_int(dict, i, "netcnt");
		if (cnt < 0)
			cnt = 0;
		
		struct user_st *user = (struct user_st*)alloc_die(
								sizeof(struct user_st) + cnt * sizeof(struct net_st));
		struct net_st *nets = (struct net_st *)user->data;

		user->name = name;
		user->pwd = pwd;
		user->nnets = cnt;

		int j = 1;
		for (; j <= cnt; j++) {
			snprintf(buf, sizeof(buf), "net%d", j);
			const char *net = get_user_str(dict, i, buf);
			if (!net) {
				DEBUG("not find section: %s", buf);
				break;
			}
			
			if (net2ip_mask((char*)net, &(nets[j - 1].ip), &(nets[j - 1].mask)) < 0)
				break;
		}
		if (j <= cnt) {
			DEBUG("net cnt error: cur: %d, expected: %d", j, cnt);
			free(user);
			break;
		}

		print_user(user);
		s_user_conf[name] = user;
	} while (++i < USER_MAX);
}

static void print_server()
{
	int cnt = s_server_conf.nnets;
	struct net_st *nets = (struct net_st*)s_server_conf.nets;

	DEBUG("server: ");
	DEBUG("        nets: %d", cnt);

	char ip_buf[16], mask_buf[16];
	for (int i = 0; i < cnt; i++) {
		DEBUG("              %s/%s", ip2str(nets[i].ip, ip_buf, sizeof(ip_buf)),
							ip2str(nets[i].mask, mask_buf, sizeof(mask_buf)));
	}
}

static void load_server_conf(dictionary *dict)
{
	int cnt = iniparser_getint(dict, "server:netcnt", 0);
	if (cnt < 0)
		return;

	struct net_st *nets = (struct net_st *)s_server_conf.nets;
	int max = sizeof(s_server_conf.nets) / sizeof(struct net_st);
	char buf[20];

	int i = 1;
	for (; i <= max; i++) {
		snprintf(buf, sizeof(buf), "server:net%d", i);
		const char *net = iniparser_getstring(dict, buf, NULL);
		if (!net)
			break;
		
		if (net2ip_mask(net, &(nets[i - 1].ip), &(nets[i - 1].mask)) < 0)
			break;
	}
	
	s_server_conf.nnets = i - 1;
	print_server();
}

int config_init()
{
	dictionary *dict = iniparser_load(FIRE_PATH);
	if (!dict) {
		DEBUG("load conf failed: %s", FIRE_PATH);
		return -1;
	}
	
	load_server_conf(dict);
	load_user_conf(dict);
	
	iniparser_freedict(dict);
	return 0;	
}
