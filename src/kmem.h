#ifndef _KMEM_H
#define _KMEM_H

#include <stdint.h>

struct kmem {
	int progfd;
	int mapfd[4];
	void *buf;
};

int kmem_read(struct kmem *kmem, uint64_t addr, void *buf, size_t size);

int kmem_open(struct kmem *kmem);
void kmem_close(struct kmem *kmem);

#endif	/* _KMEM_H */
