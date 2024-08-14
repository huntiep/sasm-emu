all: build

build:
    @gcc main.c -lncurses
    @sasm t.sasm

release:
    @gcc -o sasm-emu -O2 main.c -lncurses

run: build
    @./a.out ./bin.elf

debug: build
    @./a.out -d ./bin.elf
