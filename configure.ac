AC_PREREQ(2.61)
AC_INIT(kmemd, 1.0.0, https://github.com/wkz/kmemd/issues)

AC_GNU_SOURCE
AM_INIT_AUTOMAKE(1.11 foreign subdir-objects)
AM_SILENT_RULES(yes)

AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_CONFIG_MACRO_DIRS(m4)

AC_PROG_CC
AC_PROG_INSTALL

PKG_CHECK_MODULES([libbpf], [libbpf >= 1.0.0])

AC_HEADER_STDC
AC_CHECK_HEADERS(linux/bpf.h)

AC_OUTPUT
