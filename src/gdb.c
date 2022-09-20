#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gdb.h"

int gdb_debug = 0;

static uint8_t gdb_hex2bin_nibble(uint8_t nibble)
{
	if ((nibble >= '0') && (nibble <= '9'))
		return nibble - '0';

	return 0xa + nibble - 'a';
}

int gdb_hex2bin(void *hex, void *bin, size_t len)
{
	uint8_t *h = hex, *b = bin;

	for (; len; len--, b++) {
		*b  = gdb_hex2bin_nibble(*h++) << 4;
		*b |= gdb_hex2bin_nibble(*h++);
	}

	return 0;
}

static uint8_t gdb_bin2hex_nibble(uint8_t nibble)
{
	if (nibble <= 0x9)
		return '0' + nibble;

	return 'a' + nibble - 0xa;
}

void gdb_bin2hex(void *bin, void *hex, size_t len)
{
	uint8_t *h = hex, *b = bin;

	for (; len; len--, b++) {
		*h++ = gdb_bin2hex_nibble((*b) >> 4);
		*h++ = gdb_bin2hex_nibble((*b) & 0xf);
	}
}

int gdb_recv(FILE *fp, void *buf, size_t len)
{
	uint8_t csum_bin, csum_exp = 0;
	char csum_hex[3] = { 0 };
	uint8_t *p = buf;
	int c, n, i;

	memset(buf, 0, len);

	/* Wait for STX ($), send NAK (-) if we see unexpected data */
	for (;;) {
		c = fgetc(fp);
		switch (c) {
		case '+':
			break;
		case '$':
			goto stx;
		case EOF:
			return -EBADF;
		default:
			fputc('-', fp);
		}
	}

stx:
	/* Receive bytes until we see ETX (#) */
	for (n = 0; n < (int)len;) {
		c = fgetc(fp);
		switch (c) {
		case '#':
			goto etx;
		case EOF:
			return -EBADF;
		default:
			*p++ = c;
			csum_exp += c;
			n++;
		}
	}
etx:
	/* Receive checksum */
	for (i = 0; i < 2; i++) {
		c = fgetc(fp);
		/* printf("csum: %c\n", c); */
		if (c == EOF)
			return -EBADF;

		csum_hex[i] = c;
	}

	csum_bin = strtoul(csum_hex, NULL, 16);
	if (csum_bin != csum_exp) {
		printf("csum_bin:%2.2x csum_exp:%2.2x\n", csum_bin, csum_exp);
		fputc('-', fp);
		return -EIO;
	}

	fputc('+', fp);
	fflush(fp);

	if (gdb_debug)
		fprintf(stderr, "RECV:\"%s\"\n", (char *)buf);
	return n;
}

int gdb_send_iter(FILE *fp, int (*next)(void *ctx), void *ctx)
{
	uint8_t csum_bin = 0, csum_hex[2];
	int c;

	if (gdb_debug)
		fprintf(stderr, "SEND:\"");

	fputc('$', fp);

	while ((c = next(ctx)) >= 0) {
		fputc(c, fp);
		csum_bin += c;

		if (gdb_debug)
			fputc(c, stderr);

	}

	fputc('#', fp);

	if (gdb_debug)
		fprintf(stderr, "\"\n");

	if (c != EOF)
		/* Something went wrong, make sure to generate an
		 * incorrect checksum */
		csum_bin++;

	gdb_bin2hex(&csum_bin, csum_hex, 1);
	fwrite(csum_hex, sizeof(csum_hex), 1, fp);
	fflush(fp);

	c = fgetc(fp);
	if (c == '+')
		return 0;

	return -EIO;
}

struct gdb_send_ctx {
	uint8_t *buf;
	size_t len;
};

static int gdb_send_next(void *_ctx)
{
	struct gdb_send_ctx *ctx = _ctx;

	if (ctx->len--)
		return *(ctx->buf++);

	return EOF;
}

int gdb_send(FILE *fp, void *buf, size_t len)
{
	struct gdb_send_ctx ctx = {
		.buf = buf,
		.len = len,
	};

	return gdb_send_iter(fp, gdb_send_next, &ctx);
}
