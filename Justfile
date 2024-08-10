all: build

build:
    @gcc main.c
    @sasm t.sasm

run:
    @./a.out ./bin.elf

debug:
    @./a.out -d ./bin.elf
