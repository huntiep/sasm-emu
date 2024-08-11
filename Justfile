all: build

build:
    @gcc main.c
    @sasm t.sasm

run: build
    @./a.out ./bin.elf

debug: build
    @./a.out -d ./bin.elf
