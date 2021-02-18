#ifndef __RING_BUF_20210218__
#define __RING_BUF_20210218__

typedef struct ring_buf_st ring_buf_st;

struct ring_buf_st * ring_buf_create(int size);

void ring_buf_destroy(struct ring_buf_st *rb);

void * enqueue(struct ring_buf_st *rb, void *val);

void * dequeue(struct ring_buf_st *rb);

#endif
