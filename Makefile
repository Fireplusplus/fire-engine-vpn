ROOT_PATH=$(shell pwd)
VPN_PATH=$(ROOT_PATH)/vpn
TUNNEL_PATH=$(ROOT_PATH)/tunnel

SUBDIR=$(VPN_PATH) $(TUNNEL_PATH)

.PHONY:all
all:
	for dir in $(SUBDIR); do \
		echo "start build" $$dir; \
		cd $$dir; make || exit; \
		echo "end build" $$dir; \
	done

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
