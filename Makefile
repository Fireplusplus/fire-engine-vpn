ROOT_PATH=$(shell pwd)
SERVER_PATH=$(ROOT_PATH)
VPN_PATH=$(ROOT_PATH)/vpn
TUN_PATH=$(ROOT_PATH)/tun
CONFIG_PATH=$(ROOT_PATH)/config
UTILS_PATH=$(ROOT_PATH)/utils

SERVER=ipsec
CXX=g++
FLAGS= -Wall -Werror -levent -lcrypto -lssl -g
SUBDIRS=$(SERVER_PATH) $(VPN_PATH) $(TUN_PATH) $(CONFIG_PATH) $(UTILS_PATH)
INCLUDE=-I$(SERVER_PATH) -I$(VPN_PATH) -I$(TUN_PATH) -I$(CONFIG_PATH) -I$(UTILS_PATH)

SER_SRC=$(shell ls $(SUBDIRS) | grep -E ".cpp")
SER_OBJ=$(SER_SRC:.cpp=.o)


.PHONY:all
all:$(SERVER)

$(SERVER):$(SER_OBJ)
	$(CXX) -o $(@) $(^) $(FLAGS)
%.o:$(SERVER_PATH)/%.cpp
	$(CXX) -c $(<) $(INCLUDE) $(FLAGS)
%.o:$(VPN_PATH)/%.cpp
	$(CXX) -c $(<) $(INCLUDE) $(FLAGS)
%.o:$(TUN_PATH)/%.cpp
	$(CXX) -c $(<) $(INCLUDE) $(FLAGS)
%.o:$(CONFIG_PATH)/%.cpp
	$(CXX) -c $(<) $(INCLUDE) $(FLAGS)
%.o:$(UTILS_PATH)/%.cpp
	$(CXX) -c $(<) $(INCLUDE) $(FLAGS)

.PHONY:clean
clean:
	@rm -rf $(SERVER) *.o

.PHONY:debug
debug:
	@echo $(ROOT_PATH)
	@echo $(SER_SRC)
	@echo $(SER_OBJ)
