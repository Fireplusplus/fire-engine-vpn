#ifndef __SIMPLE_PROTO_20210110__
#define __SIMPLE_PROTO_20210110__

#include "events.h"

/* 处理接收到的命令帧 */
int on_cmd(ser_cli_node *sc, uint8_t *data);

/* 客户端发起连接 */
int start_connect(ser_cli_node *sc);

int proto_init(int server);

#endif