kmemd
-----

Explore a live Linux kernel's memory using GDB

For more background, see this [blog
entry](http://wkz.github.io/post/kmemd/)

## Building and Installing

kmem uses Autotools, so the procdure is hopefully familiar to many.

If you are building from a cloned GIT repo (as opposed to a release
tarball), you have to start by generating the configure script:

```sh
~/kmemd$ ./autogen.sh
```

To build and install with the default settings:

```sh
~/kmemd$ ./configure && make && sudo make install
```

## Using kmemd

**BEWARE:** You are about to serve up your kernel's memory over a file
or socket, i.e. basically [Hearbleed](https://heartbleed.com/) as a
service. Anyone with access to that interface will be able to read
_anything_ in there, including crypto keys and whatnot. Consider
yourself warned!

In is simplest form, kmem can be started without any arguments. As we
are going to completely root the box, we need superuser permissions.

```sh
~$ sudo kmemd
```

Without arguments, kmemd will listen for connections on the named UNIX
socket `/run/kmemd.sock`, which works well in scenarios where you want
to inspect the kernel running on your local machine.

In cases where GDB is run on a different system than the one being
inspected (which is often the case when debugging embedded systems,
for example), you will most likely want to bind to a TCP socket
instead:

```sh
~$ sudo kmemd -s :1234
```

At this point you should be able to attach to kmemd using GDB's remote
debugging facility in the normal way:

```sh
~/linux$ gdb vmlinux
(gdb) target remote the-system:1234
```

## KASLR

If your kernel is running with address layout randomization (KASLR),
the debug symbols in your `vmlinux` won't match the addresses used by
the running kernel.

You can use this GDB Python extension to compensate for it:
[gdb-linux-kaslr.py](https://gist.github.com/wkz/343f1bf91ae71ed2c140943a4f347c0c). Because
it needs to parse `/proc/kallsyms` to figure out the current base
address, GDB needs to be run as root (which it most likely needs to
connect to the default UNIX socket anyway):

```sh
~/linux$ sudo gdb
(gdb) add-vmlinux vmlinux
(gdb) target remote /run/kmemd.sock
```
