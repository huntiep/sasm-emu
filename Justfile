all: build

build:
    @gcc main.c -lncurses
    @sasm t.sasm

run: build
    @./a.out ./bin.elf

debug: build
    @./a.out -d ./bin.elf
