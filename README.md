# rv64-emu

This is a debugging emulator for RiscV64 Linux, similar to qemu-user.

If you pass the -d flag it will drop you into a debugger interface similar to GDB.

I wrote this because using gdb-multiarch + qemu-user via GDB Remote is an awful experience
and I was sick of it.
