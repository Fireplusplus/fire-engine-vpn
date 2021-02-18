#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ring_buf.h"


struct ring_buf_st {
	int size;		/* 缓冲区容量 */
	int cnt;		/* 当前缓冲数据计数 */
	int read;		/* 读位置 */
	int write;		/* 写位置 */
	void * buf[0];	/* 缓冲区 */
};

struct ring_buf_st * ring_buf_create(int size)
{
	if (size <= 0)
		return NULL;
	
	struct ring_buf_st *rb = (struct ring_buf_st *)calloc(1, 
			size * sizeof(void*) + sizeof(struct ring_buf_st));
	if (!rb)
		return NULL;
	
	rb->size = size;
	return rb;
}

void ring_buf_destroy(struct ring_buf_st *rb)
{
	if (rb)
		free(rb);
}

void * enqueue(struct ring_buf_st *rb, void *val)
{
	assert(rb && val);
	
	if (rb->cnt >= rb->size)
		return NULL;
	
	rb->buf[rb->write] = val;
	rb->write = (rb->write + 1) % rb->size;
	rb->cnt++;

	return val;
}

void * dequeue(struct ring_buf_st *rb)
{
	assert(rb);

	if (rb->cnt <= 0)
		return NULL;
	
	void *val = rb->buf[rb->read];
	rb->read = (rb->read + 1) % rb->size;
	rb->cnt--;

	return val;
}