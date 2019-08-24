TARGET=dev

dev:tun.c
	gcc -o ${TARGET} tun.c

.PHONY:clean
clean:
	rm -rf ${TARGET}

build:
	make clean && make
