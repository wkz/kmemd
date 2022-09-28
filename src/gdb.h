#ifndef _GDB_H
#define _GDB_H

struct FILE;

struct gdb_session {
	FILE *rx;
	FILE *tx;
};

extern int gdb_debug;

int gdb_hex2bin(void *hex, void *bin, size_t len);
void gdb_bin2hex(void *bin, void *hex, size_t len);

int gdb_recv(struct gdb_session *s, void *buf, size_t len);
int gdb_send(struct gdb_session *s, void *buf, size_t len);

int gdb_send_iter(struct gdb_session *s, int (*next)(void *ctx), void *ctx);

#endif	/* _GDB_H */
