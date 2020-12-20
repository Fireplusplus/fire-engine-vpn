#ifndef __LOG_20201219__
#define __LOG_20201219__

#include <string>
#include <assert.h>

#define __LOG(level, fmt, args...)		do {	\
			std::string __file(__FILE__);		\
			printf(level "%s:%d|%s|" fmt "\n", \
			__file.substr(__file.find_last_of("/")).c_str() + 1, \
			__LINE__, __FUNCTION__, ## args);	\
		} while (0)

#define DEBUG(fmt, args...)		\
		__LOG("[debug]", fmt, ## args)
#define INFO(fmt, args...)		\
		__LOG("[info]", fmt, ## args)
#define WARN(fmt, args...)		\
		__LOG("[warn]", fmt, ## args)
#define ERROR(fmt, args...)		\
		__LOG("[error]", fmt, ## args)

#define DUMP_HEX(str, buf, len)	do {			\
		char tmp[2048], *p = tmp;				\
		for (unsigned int i = 0; i < (unsigned int)len; i++) {	\
			if (i && i % 8 == 0) {p += snprintf(p, sizeof(tmp) - (p - tmp), "\n");}		\
			p += snprintf(p, sizeof(tmp) - (p - tmp), "%02x ", ((uint8_t*)buf)[i]);		\
		}	\
		DEBUG("%s:\n%s", (const char*)str, tmp);	\
	} while (0)


#endif