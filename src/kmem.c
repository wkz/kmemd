#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include <linux/version.h>

#include "kmem.h"

static char kern_log[BPF_LOG_BUF_SIZE];

#define kmem_bufsiz(_idx) ((unsigned)(16 << ((_idx) << 2)))
#define KMEM_BUFMAX       kmem_bufsiz(3)

struct kmem_args {
	uint64_t addr;
	uint16_t size;
};

static const struct bpf_insn kmem_prog[] = {
#define jgt(_size, _off)				\
	{						\
		BPF_JMP | BPF_JGT | BPF_K, BPF_REG_2,	\
		0, _off, _size				\
	}

#define ja(_off)					\
	{ BPF_JMP | BPF_JA | BPF_K, 0, 0, _off, 0 }

#define ldmap(_idx)					\
	{						\
		BPF_LD | BPF_IMM | BPF_DW, BPF_REG_1,	\
		BPF_PSEUDO_MAP_IDX_VALUE, 0, _idx	\
	},						\
	{ 0, 0, 0, 0, 0 }

#define maybe_ldmap(_idx)			\
	jgt(kmem_bufsiz(_idx), 3),		\
	ldmap(_idx),				\
	ja((2 - (_idx)) * 4 + 2)

	/* Load arguments from ctx in R1 */
	{
		BPF_LDX | BPF_MEM | BPF_DW, BPF_REG_3,
		BPF_REG_1, offsetof(struct kmem_args, addr), 0
	},
	{
		BPF_LDX | BPF_MEM | BPF_H, BPF_REG_2,
		BPF_REG_1, offsetof(struct kmem_args, size), 0
	},

	/* Select destination map based on size, to minimize copy size */
	maybe_ldmap(0),
	maybe_ldmap(1),
	maybe_ldmap(2),
	ldmap(3),

	/* Copy requested region to the selected map */
	{ BPF_JMP | BPF_CALL | BPF_K, 0, 0, 0, BPF_FUNC_probe_read_kernel },
	{ BPF_JMP | BPF_EXIT | BPF_K, 0, 0, 0, 0 }

#undef maybe_ldmap
#undef ldmap
#undef ja
#undef jgt
};

static int kmem_read_chunk(struct kmem *kmem, uint64_t addr, void *buf, size_t size)
{
	struct kmem_args args = {
		.addr = addr,
		.size = size,
	};
	struct bpf_test_run_opts runopts = {
		.sz = sizeof(runopts),
		.ctx_in = &args,
		.ctx_size_in = sizeof(args),
	};
	const uint32_t idx = 0;
	int err, i;

	err = bpf_prog_test_run_opts(kmem->progfd, &runopts);
	if (err)
		return err;

	err = -1;
	for (i = 0; i < 4; i++) {
		if (size > kmem_bufsiz(i))
			continue;

		err = bpf_map_lookup_elem(kmem->mapfd[i], &idx, kmem->buf);
		break;
	}

	memcpy(buf, kmem->buf, size);
	return err;
}

int kmem_read(struct kmem *kmem, uint64_t addr, void *buf, size_t size)
{
	int err;

	for (err = 0; !err && (size > KMEM_BUFMAX);
	     addr += KMEM_BUFMAX, buf += KMEM_BUFMAX, size -= KMEM_BUFMAX)
		err = kmem_read_chunk(kmem, addr, buf, KMEM_BUFMAX);

	return err ? : kmem_read_chunk(kmem, addr, buf, size);
}

int kmem_open(struct kmem *kmem)
{
	struct bpf_prog_load_opts progopts = {
		.sz = sizeof(progopts),
		.kern_version = LINUX_VERSION_CODE,
		.fd_array = kmem->mapfd,

		.log_level = 7,
		.log_size = sizeof(kern_log),
		.log_buf = kern_log,
	};
	int err, i;

	kmem->buf = malloc(KMEM_BUFMAX);
	if (!kmem->buf) {
		errno = ENOMEM;
		err = 1;
		goto err;
	}

	for (i = 0; i < 4; i++) {
		kmem->mapfd[i] = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL,
						sizeof(uint32_t),
						kmem_bufsiz(i), 1, NULL);
		if (kmem->mapfd[i] < 0) {
			err = kmem->mapfd[i];
			i--;
			goto err_close_maps;
		}
	}

	kmem->progfd = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT, NULL, "GPL",
				     kmem_prog,
				     sizeof(kmem_prog) / sizeof(kmem_prog[0]),
				     &progopts);
	if (kmem->progfd < 0) {
		err = kmem->progfd;
		goto err_close_maps;
	}

	return 0;

err_close_maps:
	for (; i >= 0; i--)
		close(kmem->mapfd[i]);

	free(kmem->buf);
err:
	return err;
}

void kmem_close(struct kmem *kmem)
{
	int i;

	close(kmem->progfd);

	for (i = 0; i < 4; i++)
		close(kmem->mapfd[i]);

	free(kmem->buf);
}
