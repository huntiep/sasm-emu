# Sasm-emu

This is a debugging emulator for RiscV64 Linux, similar to qemu-user.

If you pass the -d flag it will drop you into a debugger interface similar to GDB.

I wrote this because using gdb-multiarch + qemu-user via GDB Remote is an awful experience
and I was sick of it.

### Debugger Commands
- `q/CTRL-c` => Quit program.
- `ALT-k` => Switch focus to assembly view.
  - `j/k` => Move assembly view down/up.
  - `ALT-j` => Switch focus to debugger.
- `r` => Run program, ignoring any breakpoints.
- `s [x]` => Step `x` instructions. If no `x` is given, step 1 instruction.
- `b [addr]` => Set a breakpoint at address `addr`.
- `d [addr]` => Delete the breakpoint at address `addr`. If no `addr` is given, delete all breakpoints.
- `c` => Continue until the next breakpoint is reached.
- `i` => Print the current instruction.
- `x [addr]` => Print memory (dword) at address `addr`.
    - `xb [addr]` => Print byte at address `addr`.
    - `xh [addr]` => Print half at address `addr`.
    - `xw [addr]` => Print word at address `addr`.
    - `xd [addr]` => Print dword at address `addr`.
- `xs [addr]` => Print memory at address `addr` as a string.
- `p [r]` => Print the register `r` specified as `pc` or `x[0-31]`.
- `dump` => Print all registers.
- `perf` => Print performance statistics.
