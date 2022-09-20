#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <asm/ptrace.h>

#include <bpf/bpf.h>

#include <linux/version.h>

#include <netinet/ip.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "gdb.h"
#include "kmem.h"

/* Is it just me or does GDB go out of its way to make it impossible
 * to determine how long the expected response to a 'g' packet should
 * be?
 *
 * Until there's a better way, maintain a list for the platforms we
 * know about, and require everyone else to supply the -g option.
 */
#if defined(__x86_64__)
size_t gsize = 560;
#elif defined(__i386__)
size_t gsize = 312;
#else
size_t gsize = 0;
#endif

struct kmem kmem;

struct serve_m_ctx {
	uint8_t *buf;
	size_t len;

	bool nibble;
	uint8_t hex[2];
};

int serve_m_next(void *_ctx)
{
	struct serve_m_ctx *ctx = _ctx;

	if (ctx->nibble) {
		ctx->nibble = false;
		return ctx->hex[1];
	}

	if (!ctx->len--)
		return EOF;

	gdb_bin2hex(ctx->buf++, ctx->hex, 1);
	ctx->nibble = true;

	return ctx->hex[0];
}

int serve_m(FILE *session, uint8_t *pkt)
{
	struct serve_m_ctx ctx = {};
	unsigned long long addr;
	char *delim;
	void *buf;
	int err;

	addr = strtoull((char *)&pkt[1], &delim, 16);
	if (*delim != ',')
		return -EINVAL;

	delim++;

	ctx.len = strtoul(delim, NULL, 16);
	if (ctx.len == ULONG_MAX)
		return -EINVAL;

	buf = malloc(ctx.len);
	if (!buf)
		return -ENOMEM;

	err = kmem_read(&kmem, addr, buf, ctx.len);
	if (err) {
		free(buf);
		gdb_send(session, NULL, 0);
		return err;
	}

	ctx.buf = buf;
	err = gdb_send_iter(session, serve_m_next, &ctx);

	free(buf);
	return err;
}

int serve_g_next(void *_left)
{
	size_t *left = _left;
	if ((*left)--)
		return '0';

	return EOF;
}

int serve_g(FILE *session)
{
	/* Two ASCII hex digits per byte */
	size_t left = gsize * 2;

	return gdb_send_iter(session, serve_g_next, &left);
}

void serve(FILE *session)
{
	uint8_t pkt[0x100];
	int len, err = 0;

	if (gdb_debug)
		fprintf(stderr, "Session started\n");

	while (!err && (len = gdb_recv(session, pkt, sizeof(pkt))) >= 0) {
		switch (pkt[0]) {
		case '?':
			err = gdb_send(session, "S05", 3);
			break;
		case 'g':
			err = serve_g(session);
			break;
		case 'm':
			err = serve_m(session, pkt);
			break;
		default:
			err = gdb_send(session, NULL, 0);
		}
	}

	if (gdb_debug)
		fprintf(stderr, "Session ended (len:%d err:%d)\n", len, err);
}


int serve_file(const char *path)
{
	FILE *session;

	session = fopen(path, "a+");
	if (!session) {
		fprintf(stderr, "Unable to open \"%s\": %m\n", path);
		return 1;
	}

	fprintf(stderr, "Opened %s\n", path);
	serve(session);
	fclose(session);
	return 0;
}

int bind_unix(const char *path)
{
	struct sockaddr_un sa = {
		.sun_family = AF_UNIX,
	};
	struct stat st;
	int err, sk;

	strcpy(sa.sun_path, path);

	sk = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sk < 0) {
               perror("socket(unix)");
               return sk;
	}

	err = stat(path, &st);
	if (!err && ((st.st_mode & S_IFMT) == S_IFSOCK))
		unlink(sa.sun_path);

	err = bind(sk, (const struct sockaddr *) &sa, sizeof(sa));
	if (err) {
		perror("bind(unix)");
		return err;
	}

	return sk;
}

int bind_inet(const char *addr)
{
	static const struct addrinfo hints = {
		.ai_flags = AI_PASSIVE | AI_V4MAPPED | AI_ADDRCONFIG,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	static const int enable = 1;

	struct addrinfo *ai, *ais;
	char *addr2, *host, *port;
	int err, sk;

	host = addr2 = strdup(addr);

	/* Port must be specified, so remove that first */
	port = rindex(host, ':');
	*(port++) = '\0';

	switch (*host) {
	case '\0':
		/* :<port> */
		host = NULL;
		break;
	case '[':
		/* [<ipv6>]:<port> (RFC5952, section 6) */
		if (host[strlen(host) - 1] == ']') {
			host[strlen(host) - 1] = '\0';
			host++;
		}
		break;
	}

	err = getaddrinfo(host, port, &hints, &ais);
	free(addr2);
	if (err) {
		fprintf(stderr, "Unable to resolve %s\n", addr);
		return -1;
	}

	for (ai = ais; ai; ai = ai->ai_next) {
		sk = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sk < 0)
			continue;

		err = setsockopt(sk, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
				 &enable, sizeof(enable));
		if (err)
			goto try_next;

		err = bind(sk, ai->ai_addr, ai->ai_addrlen);
		if (err)
			goto try_next;

		freeaddrinfo(ais);
		return sk;

	try_next:
		close(sk);
	}

	freeaddrinfo(ais);

	fprintf(stderr, "Unable to bind to %s\n", addr);
	return -1;
}

int serve_sock(const char *addr)
{
	int err, sk, fd;
	FILE *session;

	if (strchr(addr, ':'))
		sk = bind_inet(addr);
	else
		sk = bind_unix(addr);

	if (sk < 0)
		return 1;

	err = listen(sk, 1);
	if (err) {
		perror("listen");
		return 1;
	}

	fprintf(stderr, "Listening on %s\n", addr);

	for (;;) {
		fd = accept(sk, NULL, NULL);
		if (fd < 0) {
			perror("accept");
			break;
		}

		session = fdopen(fd, "a+");
		if (!session) {
			perror("fdopen");
			break;
		}

		serve(session);

		fclose(session);
	}

	return 0;
}

static void usage()
{
	fputs("kmemd - Serve live kernel memory over GDB RSP\n"
	      "\n"
	      "Usage:\n"
	      "  kmemd [options] [-s <path>]        -- Listen on UNIX socket\n"
	      "  kmemd [options] -s [<host>]:<port> -- Listen on TCP socket\n"
	      "  kmemd [options] -f <path>          -- Communicate using file\n"
	      "\n"
	      "  By default, kmemd listens on the named UNIX domain\n"
	      "  socket /run/kmemd.sock\n"
	      "\n"
	      "Options:\n"
	      "  -d             Enable debug output.\n"
	      "  -f PATH        Use file for communicating with GDB.\n"
	      "  -g SIZE        Reply size of 'g' messages (0 - 4k).\n"
	      "  -h             Print usage message and exit.\n"
	      "  -s ADDRESS     Listen for GDB connections on UNIX or TCP socket.\n"
	      "  -v             Print version information.\n",
	      stderr);
}

static const char *sopts = "df:g:hs:v";
static struct option lopts[] = {
	{ "debug",   no_argument,       0, 'd' },
	{ "file",    required_argument, 0, 'f' },
	{ "g-size",  required_argument, 0, 'g' },
	{ "help",    no_argument,       0, 'h' },
	{ "socket",  required_argument, 0, 's' },
	{ "version", no_argument,       0, 'v' },

	{ NULL }
};

int main(int argc, char **argv)
{
	char *file = NULL, *sock = "/run/kmemd.sock";
	int err, opt;
	unsigned long g;

	while ((opt = getopt_long(argc, argv, sopts, lopts, NULL)) > 0) {
		switch (opt) {
		case 'd':
			gdb_debug++;
			break;
		case 'f':
			file = optarg;
			break;
		case 'g':
			g = strtoul(optarg, NULL, 0);
			if (g > (4 << 10)) {
				fprintf(stderr, "Invalid g size '%s'\n\n", optarg);
				usage();
				exit(1);
			}

			gsize = g;
			break;
		case 'h':
			usage();
			return 0;
		case 's':
			sock = optarg;
			break;
		case 'v':
			puts(PACKAGE_STRING);
			return 0;

		default:
			fprintf(stderr, "Unknown option '%c'\n\n", opt);
			usage();
			return 1;
		}
	}

	if (!gsize) {
		fprintf(stderr,
			"Size of 'g' packet is not known, "
			"please supply via -g option\n");
		usage();
		return 1;
	} else if (gdb_debug) {
		fprintf(stderr, "Using 'g' size of %zu bytes\n", gsize);
	}

	err = kmem_open(&kmem);
	if (err) {
		fprintf(stderr, "Unable to create kernel memory reader: %m\n");
		return 1;
	}

	return file ? serve_file(file) : serve_sock(sock);
}
