TARGET=dev
TUN_DIR=./tun
INCLUDE=${TUN_DIR}

dev:
	gcc -o ${TARGET} test.c ${TUN_DIR}/tun.c -I ${INCLUDE}

.PHONY:clean
clean:
	rm -rf ${TARGET}

build:
	make clean && make
