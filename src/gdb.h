#ifndef _GDB_H
#define _GDB_H

struct FILE;

extern int gdb_debug;

int gdb_hex2bin(void *hex, void *bin, size_t len);
void gdb_bin2hex(void *bin, void *hex, size_t len);

int gdb_recv(FILE *fp, void *buf, size_t len);
int gdb_send(FILE *fp, void *buf, size_t len);

int gdb_send_iter(FILE *fp, int (*next)(void *ctx), void *ctx);

#endif	/* _GDB_H */
