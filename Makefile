ROOT_PATH=$(shell pwd)
SERVER_PATH=$(ROOT_PATH)
EVENTS_PATH=$(ROOT_PATH)/events
TUN_PATH=$(ROOT_PATH)/tun

SERVER=ipsec
CXX=g++
FLAGS=-levent -g
SUBDIRS=$(SERVER_PATH) $(EVENTS_PATH) $(TUN_PATH)
INCLUDE=-I$(SERVER_PATH) -I$(EVENTS_PATH) -I$(TUN_PATH)

SER_SRC=$(shell ls $(SUBDIRS) | grep -E ".cpp")
SER_OBJ=$(SER_SRC:.cpp=.o)


.PHONY:all
all:$(SERVER)

$(SERVER):$(SER_OBJ)
	$(CXX) -o $(@) $(^) $(FLAGS)
%.o:$(SERVER_PATH)/%.cpp
	$(CXX) -c $(<) $(INCLUDE) $(FLAGS)
%.o:$(EVENTS_PATH)/%.cpp
	$(CXX) -c $(<) $(INCLUDE) $(FLAGS)
%.o:$(TUN_PATH)/%.cpp
	$(CXX) -c $(<) $(INCLUDE) $(FLAGS)

.PHONY:clean
clean:
	@rm -rf $(SERVER) *.o

.PHONY:debug
debug:
	@echo $(ROOT_PATH)
	@echo $(SER_SRC)
	@echo $(SER_OBJ)