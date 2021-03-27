#ifndef __CONFIG_2021024__
#define __CONFIG_2021024__

int config_init();

int check_user(const struct user_st *user, const char *pwd);

const char * get_user_name(const struct user_st *user);

int get_user_net(const struct user_st *user, char *buf, int size);

const struct user_st * get_user(const char *name);

#endif