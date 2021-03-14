#include <iostream>
#include <string>
#include <unordered_map>
#include <iniparser.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

using namespace std;

#include "user.h"
#include "proto.h"
#include "mem.h"

/*
name = test
pwd = test
netcnt = 2
net1 = 192.168.100.0/255.255.255.0
net2 = 192.168.200.0/255.255.255.0
*/


struct user_st {
	string name;
	string pwd;
	int netcnt;
	struct net_st net[0];
};

static unordered_map<string, struct user_st *> s_user_conf;

#define USER_MAX	20000
#define USER_PATH	"/etc/user.ini"

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

static int net2ip_mask(char *net, uint32_t *ip, uint32_t *mask)
{
	char *mk = net;
	while (*mk != '/' && *mk != '\0')
		mk++;

	if (*mk != '/')
		return -1;
	
	*mk = '\0';
	mk++;
	
	if (inet_pton(AF_INET, net, ip) < 0 ||
		inet_pton(AF_INET, mk, mask) < 0)
		return -1;
	
	return 0;
}

int check_user(const char *name, const char *pwd)
{
	if (!name || !pwd)
		return -1;
	
	unordered_map<string, struct user_st *>::iterator it = s_user_conf.find(name);
	if (it == s_user_conf.end()) {
		DEBUG("not found user: %s", name);
		return -1;
	}
	
	if (it->second->pwd != pwd) {
		DEBUG("pwd not match: pwd: %s, expected: %s", pwd, it->second->pwd.c_str());
		return -1;
	}
	
	return 0;
}

int user_init()
{
	dictionary *dict = iniparser_load(USER_PATH);
	if (!dict)
		return -1;
	
	int i = 1;
	
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
		
		struct user_st *user = (struct user_st*)alloc_die(sizeof(struct user_st) + cnt * sizeof(struct net_st));
		struct net_st *nets = user->net;

		user->name = name;
		user->pwd = pwd;

		char buf[5];
		int j = 1;
		for (; j <= cnt; j++) {
			snprintf(buf, sizeof(buf), "net%d", j);
			const char *net = get_user_str(dict, i, buf);
			if (!net)
				break;
			
			if (net2ip_mask((char*)net, &(nets[j - 1].ip), &(nets[j - 1].mask)) < 0)
				break;
		}
		if (j <= cnt) {
			free(user);
			break;
		}
		
		s_user_conf[name] = user;
	} while (++i < USER_MAX);

	iniparser_freedict(dict);
	return 0;	
}
