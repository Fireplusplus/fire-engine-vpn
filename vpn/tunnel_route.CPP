#include <stdint.h>
#include "mem.h"
#include "proto.h"
#include "ev.h"

#define TUN_NAME	"tun"
#define TABLE_ID	17

struct route_st {
	int nnets;
	uint8_t data[0];
};

static int route_add(int table, const char *dst, const char *dev);

static void __tunnel_route_add(void *arg)
{
	assert(arg);

	struct route_st *route = (struct route_st *)arg;
	struct net_st *nets = (struct net_st *)route->data;
	int nnets = route->nnets;

	DEBUG("nnets: %d", nnets);

	static char buf_ip[16], buf[50];

	for (int i = 0; i < nnets; i++) {
		snprintf(buf, sizeof(buf), "%s/%d", 
				ip2str(nets[i].ip, buf_ip, sizeof(buf_ip)), 
				mask2bit(nets[i].mask));
		
		if (route_add(TABLE_ID, buf, TUN_NAME) < 0) {
			WARN("add tunnel route(%s) in table(%d) to dev(%s) failed", buf, TABLE_ID, TUN_NAME);
		} else {
			INFO("add tunnel route(%s) in table(%d) to dev(%s) ok", buf, TABLE_ID, TUN_NAME);
		}
	}

	free(route);
}

static int tunnel_route_add(int nnets, struct net_st *nets)
{
	if (!nnets || !nets)
		return -1;

	struct route_st *route = (struct route_st*)alloc_die(sizeof(struct route_st) + 
									sizeof(struct net_st) * nnets);
	
	route->nnets = nnets;
	memcpy(route->data, nets, nnets * sizeof(*nets));

	if (ev_timer(3, __tunnel_route_add, route) < 0)
		return -1;
	
	return 0;
}

#include <netlink/route/route.h>
#include <netlink/route/link.h>

typedef int	(*route_op)(struct nl_sock *, struct rtnl_route *, int);

static inline int route_ctrl(int table, const char *dst, const char *dev, route_op fn)
{
	int ifindex = 0, err = 0;
	struct rtnl_nexthop *nh = NULL;
	struct nl_addr *addr = NULL;
	struct nl_sock *sock = NULL;
	struct nl_cache *cache = NULL;
	
	struct rtnl_route *route = rtnl_route_alloc();
	if (!route) {
		return -1;
	}

	rtnl_route_set_family(route, AF_INET);
	rtnl_route_set_table(route, table);
	
	err = nl_addr_parse(dst, AF_INET, &addr);
	if (err < 0) {
		DEBUG("nl_addr_parse failed: %s", nl_geterror(err));
		goto failed;
	}
	
	rtnl_route_set_dst(route, addr);
	
	sock = nl_socket_alloc();
	if (!sock) {
		goto failed;
	}
	
	err = nl_connect(sock, NETLINK_ROUTE);
	if (err < 0) {
		DEBUG("nl_connect failed: %s\n", nl_geterror(err));
		goto failed;
	}
	
	if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache) < 0) {
		goto failed;
	}
	
	ifindex = rtnl_link_name2i(cache, dev);
	if (!ifindex) {
		DEBUG("rtnl_link_name2i failed: %s\n", nl_geterror(ifindex));
		goto failed;
	}
	
	nh = rtnl_route_nh_alloc();
	if (!nh) {
		goto failed;
	}
	
	rtnl_route_nh_set_ifindex(nh, ifindex);
	rtnl_route_add_nexthop(route, nh);
	nh = NULL;
	
	err = fn(sock, route, 0);
	if (err < 0) {
		DEBUG("route operate failed: %s\n", nl_geterror(err));
		goto failed;
	}
	
	return 0;

failed:
	if (route)
		rtnl_route_put(route);
	if (nh)
		rtnl_route_nh_free(nh);
	if (addr)
		nl_addr_put(addr);
	if (sock)
		nl_socket_free(sock);
	if (cache)
		nl_cache_put(cache);
	
	return -1;
}

static int route_add(int table, const char *dst, const char *dev)
{
	return route_ctrl(table, dst, dev, rtnl_route_add);
}

#if 0
static int route_del(int table, const char *dst, const char *dev)
{
	return route_ctrl(table, dst, dev, rtnl_route_delete);
}
#endif