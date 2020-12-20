# Fire Engine VPN
你的新一代vpn引擎--消防车！

1.开启linux的ip代理转发功能,作为路由器角色
	echo 1 > /proc/sys/net/ipv4/ip_forward

2.添加内网路由至tun口
	a.添加路由表
		ip rule add table 17 pref 10
	b.添加路由至某条路由表
		ip route add 14.254.254.0/255.255.255.0 dev vpntun proto static table 17
	c.可以在tun口抓到内网pc ping 14网段的包了
