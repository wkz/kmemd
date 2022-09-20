sbin_PROGRAMS = kmemd

kmemd_CPPFLAGS = -include $(top_builddir)/config.h
kmemd_CFLAGS   = -Wall -Wextra
kmemd_CFLAGS  += $(libbpf_CFLAGS)
kmemd_LDADD    = $(libbpf_LIBS)
kmemd_SOURCES  = gdb.c gdb.h kmem.c kmem.h kmemd.c
