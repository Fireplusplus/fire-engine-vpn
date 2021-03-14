ROOT_PATH=$(shell pwd)
VPN_PATH=$(ROOT_PATH)/vpn
TUNNEL_PATH=$(ROOT_PATH)/tunnel
LIB_PATH=/lib64
INCLUDE_PATH=/usr/local/include

SUBDIR=$(VPN_PATH) $(TUNNEL_PATH)

.PHONY:all
all:
	for dir in $(SUBDIR); do \
		echo "start build" $$dir; \
		cd $$dir; make || exit; \
		echo "end build" $$dir; \
	done

depend:lib-ini

depend-clean:lib-ini-clean

lib-ini:
	rm -rf iniparser && \
	git clone https://codechina.csdn.net/mirrors/ndevilla/iniparser.git && \
	cd iniparser && \
	git checkout -q f858275f7f307eecba84c2f5429483f9f28007f8 && \
	make && mkdir -p $(INCLUDE_PATH)/ini && \
	cp src/*.h $(INCLUDE_PATH)/ini && \
	cp libiniparser.so.1 $(LIB_PATH)/libiniparser.so -f || exit

lib-ini-clean:
	rm -rf iniparser $(INCLUDE_PATH)/ini $(LIB_PATH)/libiniparser.so*

.PHONY:clean
clean:
	for dir in $(SUBDIR); do \
		echo "start clean" $$dir; \
		cd $$dir; make clean; \
		echo "end clean" $$dir; \
	done

.PHONY:debug
debug:
	@echo $(ROOT_PATH)
