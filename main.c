#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <ncurses.h>

void ecall(uint64_t registers[32]);
int print_instruction(WINDOW*, uint32_t);
void prompt();

uint16_t RISCV = 0xf3;

#define ALT_J (1024+'j')
#define ALT_K (1024+'k')

struct ehdr {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct perf {
    uint64_t instruction_count;
    uint64_t loads;
    uint64_t stores;
    uint64_t syscalls;
};

void print_usage(char* prog) {
    fprintf(stderr, "USAGE: %s <EXE>\n\t-d: Debugger mode.\n", prog);
}

WINDOW* asm_win;
WINDOW* cli_win;

uint32_t* pc = 0;
uint32_t* instructions = 0;
struct perf perf = {};
uint64_t registers[32] = {};
int debug = 0;
int curses = 0;
uint64_t heap_start = 0;
uint64_t heap_end = 0;
char* history[100] = {};
int history_start = 0;
int history_end = 0;


void segfault(int sig_num) {
    fprintf(stderr, "SEGFAULT\n");
    while (1) {
        prompt();
    }
}

void sigint(int sig_num) {
    endwin();
    exit(1);
}

int main(int argc, char* argv[]) {
    char* prog = argv[0];
    if (argc < 2) {
        print_usage(prog);
        return 1;
    }

    argc--;
    argv++;
    if (strcmp(argv[0], "-d") == 0) {
        debug = 1;
        if (argc == 1) {
            print_usage(prog);
            return 1;
        }
        argc--;
        argv++;
    }

    int exe = openat(AT_FDCWD, argv[0], O_RDONLY);
    struct ehdr hdr;
    read(exe, (char*) &hdr, sizeof(struct ehdr));

    if (hdr.e_machine != RISCV || hdr.e_type != 2) {
        fprintf(stderr, "Bad exe\n");
        return 1;
    }

    pc = (uint32_t*) hdr.e_entry;
    instructions = (uint32_t*) hdr.e_entry;

    struct phdr* phdrs = calloc(hdr.e_phnum, sizeof(struct phdr));
    read(exe, (char*) phdrs, sizeof(struct phdr) * hdr.e_phnum);

    for (int i = 0; i < hdr.e_phnum; i++) {
        int flags = PROT_READ;
        if (phdrs[i].p_flags == 6) {
            flags |= PROT_WRITE;
        }
        char* pos = (char*) (phdrs[i].p_vaddr - phdrs[i].p_offset);
        uint64_t size = (phdrs[i].p_offset + phdrs[i].p_filesz + 4095) & (-4096);

        if (((uint64_t) pos) + size > heap_start) {
            heap_start = ((uint64_t) pos) + size;
            heap_end = ((uint64_t) pos) + size;
        }

        if (phdrs[i].p_flags == 5) {
            mmap(pos, size, flags, MAP_PRIVATE|MAP_FIXED, exe, 0);
            //instructions = (uint32_t*) mmap(pos, size, flags, MAP_PRIVATE|MAP_FIXED, exe, 0);
        } else {
            mmap(pos, size, flags, MAP_PRIVATE|MAP_FIXED, exe, 0);
        }
    }
    free(phdrs);

    // stack
    uint64_t STACK_SIZE = 8392704;
    char* stack = mmap((char*) 0x4000000000, STACK_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
    // copy argc/argv to stack, skipping emulator args
    uint64_t* sp = (uint64_t*) (stack + STACK_SIZE - (8 * argc + 8));
    sp[0] = (uint64_t) argc;
    for (int i = 0; i < argc; i++) {
        sp[i + 1] = (uint64_t) argv[i];
    }

    if (debug) {
        initscr();
        cbreak();
        noecho();
        keypad(stdscr, TRUE);
        define_key("\033j", ALT_J);
        define_key("\033k", ALT_K);

        int h, w;
        getmaxyx(stdscr, h, w);
        asm_win = newwin((h/2) - 1, w, 0, 0);
        cli_win = newwin(h-(h/2), w, h/2, 0);
        scrollok(cli_win, TRUE);

        wrefresh(stdscr);
        move((h/2) - 1, 0);
        whline(stdscr, ACS_HLINE, w);
        wrefresh(stdscr);
        wmove(cli_win, h-(h/2)-1, 0);
        wrefresh(cli_win);

        curses = 1;
        signal(SIGINT, sigint);
        signal(SIGSEGV, segfault);
    }

    registers[2] = (uint64_t) sp;

    while (1) {
        if (debug) {
            prompt();
        }
        uint32_t instruction = pc[0];
        perf.instruction_count++;
        pc++;
        uint32_t opcode = instruction & 0b1111111;
        if (opcode == 0b0110011) {
            // R
            uint32_t rd = (instruction >> 7) & 0b11111;
            uint32_t rs1 = (instruction >> 15) & 0b11111;
            uint32_t rs2 = (instruction >> 20) & 0b11111;
            uint32_t funct3 = (instruction >> 12) & 0b111;
            uint32_t funct7 = instruction >> 25;

            uint64_t left = registers[rs1];
            uint64_t right = registers[rs2];
            uint64_t value;
            if (funct3 == 0) {
                if (funct7 == 0x00) {
                    // add
                    value = left + right;
                } else if (funct7 == 0x20) {
                    // sub
                    value = left - right;
                } else if (funct7 == 0x01) {
                    // mul
                    value = left * right;
                }
            } else if (funct3 == 4) {
                if (funct7 == 0x00) {
                    // xor
                    value = left ^ right;
                } else if (funct7 == 0x01) {
                    // div
                    value = left / right;
                }
            } else if (funct3 == 6) {
                if (funct7 == 0x00) {
                    // or
                    value = left | right;
                } else if (funct7 == 0x01) {
                    // rem
                    value = left % right;
                }
            } else if (funct3 == 7) {
                // and
                    value = left & right;
            } else if (funct3 == 1) {
                // sll
                value = left << right;
            } else if (funct3 == 5) {
                if (funct7 == 0x00) {
                    // srl
                    // TODO
                } else if (funct7 == 0x20) {
                    // sra
                    value = left >> right;
                }
            } else if (funct3 == 2) {
                // slt
                // TODO
            } else if (funct3 == 3) {
                // sltu
                // TODO
            }
            if (rd > 0) {
                registers[rd] = value;
            }
        } else if (opcode == 0b0010011) {
            // I
            uint32_t rd = (instruction >> 7) & 0b11111;
            uint32_t rs1 = (instruction >> 15) & 0b11111;
            uint32_t funct3 = (instruction >> 12) & 0b111;
            uint64_t imm = instruction >> 20;
            uint64_t m = 1U << (12 - 1);
            imm = (imm ^ m) - m;

            uint64_t left = registers[rs1];
            uint64_t value;
            if (funct3 == 0) {
                // addi
                value = left + imm;
            } else if (funct3 == 4) {
                // xori
                value = left ^ imm;
            } else if (funct3 == 6) {
                // ori
                value = left | imm;
            } else if (funct3 == 7) {
                // andi
                value = left & imm;
            } else if (funct3 == 1) {
                // slli
                value = left << imm;
            } else if (funct3 == 5) {
                if ((imm >> 5) == 0x20) {
                    // srai
                    value = left >> imm;
                } else {
                    // srli
                    // TODO
                }
            } else if (funct3 == 2) {
                // slti
                // TODO
            } else if (funct3 == 3) {
                // sltiu
                // TODO
            }
            if (rd > 0) {
                registers[rd] = value;
            }
        } else if (opcode == 0b0000011) {
            // I2
            perf.loads++;
            uint32_t rd = (instruction >> 7) & 0b11111;
            uint32_t rs1 = (instruction >> 15) & 0b11111;
            uint32_t funct3 = (instruction >> 12) & 0b111;
            uint64_t imm = instruction >> 20;
            uint64_t m = 1U << (12 - 1);
            imm = (imm ^ m) - m;

            uint64_t loc = registers[rs1] + imm;
            uint64_t value;
            if (funct3 == 0) {
                // lb
                value = ((char*) loc)[0];
                uint64_t m = 1U << (8 - 1);
                value = (value ^ m) - m;
            } else if (funct3 == 1) {
                // lh
                value = ((uint16_t*) loc)[0];
                uint64_t m = 1U << (16 - 1);
                value = (value ^ m) - m;
            } else if (funct3 == 2) {
                // lw
                value = ((uint32_t*) loc)[0];
                uint64_t m = 1U << (32 - 1);
                value = (value ^ m) - m;
            } else if (funct3 == 3) {
                // ld
                value = ((uint64_t*) loc)[0];
            } else if (funct3 == 4) {
                // lbu
                value = ((char*) loc)[0];
            } else if (funct3 == 5) {
                // lhu
                value = ((uint16_t*) loc)[0];
            } else if (funct3 == 6) {
                // lwu
                value = ((uint32_t*) loc)[0];
            }
            if (rd > 0) {
                registers[rd] = value;
            }
        } else if (opcode == 0b0100011) {
            // S
            perf.stores++;
            uint32_t rs1 = (instruction >> 20) & 0b11111;
            uint32_t rd = (instruction >> 15) & 0b11111;
            uint32_t funct3 = (instruction >> 12) & 0b111;
            uint64_t imm = ((instruction >> 20) & 0xfe0) | ((instruction >> 7) & 0x1f);
            uint64_t m = 1U << (12 - 1);
            imm = (imm ^ m) - m;

            uint64_t value = registers[rs1];
            uint64_t loc = registers[rd] + imm;
            if (funct3 == 0) {
                // sb
                char* l = (char*) loc;
                l[0] = (uint8_t) value;
            } else if (funct3 == 1) {
                // sh
                uint16_t* l = (uint16_t*) loc;
                l[0] = (uint16_t) value;
            } else if (funct3 == 2) {
                // sw
                uint32_t* l = (uint32_t*) loc;
                l[0] = (uint32_t) value;
            } else if (funct3 == 3) {
                // sd
                uint64_t* l = (uint64_t*) loc;
                l[0] = value;
            }
        } else if (opcode == 0b1100011) {
            // B
            pc--;
            uint32_t rs1 = (instruction >> 15) & 0b11111;
            uint32_t rs2 = (instruction >> 20) & 0b11111;
            uint32_t funct3 = (instruction >> 12) & 0b111;
            uint64_t imm = ((instruction & 0x80000000) >> 19) | ((instruction & 0x7e000000) >> 20) |
                           ((instruction & 0xf00) >> 7) | ((instruction & 0x80) << 4);
            uint64_t m = 1U << (13 - 1);
            imm = (imm ^ m) - m;
            uint64_t left = registers[rs1];
            uint64_t right = registers[rs2];
            if (funct3 == 0 && left == right) {
                // beq
                pc = (uint32_t*) (((uint64_t) pc) + imm);
            } else if (funct3 == 1 && left != right) {
                // bne
                pc = (uint32_t*) (((uint64_t) pc) + imm);
            } else if (funct3 == 4 && (int64_t)left < (int64_t) right) {
                // blt
                pc = (uint32_t*) (((uint64_t) pc) + imm);
            } else if (funct3 == 5 && (int64_t)left >= (int64_t) right) {
                // bge
                pc = (uint32_t*) (((uint64_t) pc) + imm);
            } else if (funct3 == 6 && left < right) {
                // bltu
                pc = (uint32_t*) (((uint64_t) pc) + imm);
            } else if (funct3 == 7 && left >= right) {
                // bgeu
                pc = (uint32_t*) (((uint64_t) pc) + imm);
            } else {
                pc++;
            }
        } else if (opcode == 0b1101111) {
            // JAL
            uint32_t rd = (instruction >> 7) & 0b11111;
            uint64_t imm = ((instruction & 0x80000000) >> 11) | ((instruction & 0x7fe00000) >> 20) |
                           ((instruction & 0x100000) >> 9) | (instruction & 0xff000);
            uint64_t m = 1U << (21 - 1);
            imm = (imm ^ m) - m;
            if (rd > 0) {
                registers[rd] = (uint64_t) pc;
            }
            pc--;
            pc = (uint32_t*) (((uint64_t) pc) + imm);
        } else if (opcode == 0b1100111) {
            // JALR
            uint32_t rd = (instruction >> 7) & 0b11111;
            uint64_t rs = registers[(instruction >> 15) & 0b11111];
            uint64_t offset = instruction >> 20;
            uint64_t m = 1U << (12 - 1);
            offset = (offset ^ m) - m;
            if (rd > 0) {
                registers[rd] = (uint64_t) pc;
            }
            pc = (uint32_t*) (rs + offset);
        } else if (opcode == 0b0110111) {
            // LUI
            uint64_t imm = (instruction >> 12) << 12;
            uint64_t m = 1U << (32 - 1);
            imm = (imm ^ m) - m;
            uint32_t rd = (instruction >> 7) & 0b11111;
            registers[rd] = imm;
        } else if (opcode == 0b0010111) {
            // AUIPC
            pc--;
            uint64_t imm = (instruction >> 12) << 12;
            uint64_t m = 1U << (32 - 1);
            imm = (imm ^ m) - m;
            imm = imm + (uint64_t) pc;
            uint32_t rd = (instruction >> 7) & 0b11111;
            registers[rd] = imm;
            pc++;
        } else if (opcode == 0b1110011) {
            if ((instruction & (1 << 12)) != 0) {
                // TODO: ebreak
            } else {
                perf.syscalls++;
                if (registers[17] == 214) {
                    // brk
                    if (registers[10] == 0) {
                        registers[10] = heap_end;
                    } else if (registers[10] > heap_end) {
                        uint64_t size = ((registers[10] - heap_end) + 4095) & (-4096);
                        mmap((char*) heap_end, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
                        heap_end += size;
                    }
                } else {
                    ecall(registers);
                }
            }
        } else {
            fprintf(stderr, "ILLEGAL INSTRUCTION: %x at %x\n", instruction, pc);
            if (curses) {
                endwin();
            }
            return 1;
        }
    }
    if (curses) {
        endwin();
    }
}

void ecall(uint64_t registers[32]) {
    // exit
    if (registers[17] == 93) {
        if (debug) {
            while (1) { prompt(); }
        }
        if (curses) {
            endwin();
        }
    }
    uint16_t syscalls_map[320] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 257, 3, 0, 0, 0, 217, 8, 0,
                                 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 60, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 12, 11, 0, 0, 0, 0, 0, 0, 9, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 332, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};


    register uint64_t r10 asm("r10") = registers[13];
    register uint64_t r8 asm("r8") = registers[14];
    register uint64_t r9 asm("r9") = registers[15];
    uint64_t ret;
    __asm volatile (
        "syscall"
        : "=a"(ret)
        : "a"(syscalls_map[registers[17]]), "D"(registers[10]), "S"(registers[11]), "d"(registers[12]), "r"(r10), "r"(r8), "r"(r9)//, "D"(registers[16])
        : "rcx", "r11", "memory"
    );
    registers[10] = ret;
}

int print_instruction(WINDOW* win, uint32_t instruction) {
    uint32_t opcode = instruction & 0b1111111;
    if (opcode == 0b0110011) {
        // R
        uint32_t rd = (instruction >> 7) & 0b11111;
        uint32_t rs1 = (instruction >> 15) & 0b11111;
        uint32_t rs2 = (instruction >> 20) & 0b11111;
        uint32_t funct3 = (instruction >> 12) & 0b111;
        uint32_t funct7 = instruction >> 25;

        if (funct3 == 0) {
            if (funct7 == 0x00) {
                // add
                wprintw(win, "(add ");
            } else if (funct7 == 0x20) {
                // sub
                wprintw(win, "(sub ");
            } else if (funct7 == 0x01) {
                // mul
                wprintw(win, "(mul ");
            }
        } else if (funct3 == 4) {
            if (funct7 == 0x00) {
                // xor
                wprintw(win, "(xor ");
            } else if (funct7 == 0x01) {
                // div
                wprintw(win, "(div ");
            }
        } else if (funct3 == 6) {
            if (funct7 == 0x00) {
                // or
                wprintw(win, "(or ");
            } else if (funct7 == 0x01) {
                // rem
                wprintw(win, "(rem ");
            }
        } else if (funct3 == 7) {
            // and
            wprintw(win, "(and ");
        } else if (funct3 == 1) {
            // sll
            wprintw(win, "(sll ");
        } else if (funct3 == 5) {
            if (funct7 == 0x00) {
                // srl
                wprintw(win, "(srl ");
            } else if (funct7 == 0x20) {
                // sra
                wprintw(win, "(sra ");
            }
        } else if (funct3 == 2) {
            // slt
            wprintw(win, "(slt ");
        } else if (funct3 == 3) {
            // sltu
            wprintw(win, "(sltu ");
        }
        wprintw(win, "x%d x%d x%d)\n", rd, rs1, rs2);
    } else if (opcode == 0b0010011) {
        // I
        uint32_t rd = (instruction >> 7) & 0b11111;
        uint32_t rs1 = (instruction >> 15) & 0b11111;
        uint32_t funct3 = (instruction >> 12) & 0b111;
        uint64_t imm = instruction >> 20;
        uint64_t m = 1U << (12 - 1);
        imm = (imm ^ m) - m;

        if (funct3 == 0) {
            // addi
            wprintw(win, "(addi ");
        } else if (funct3 == 4) {
            // xori
            wprintw(win, "(xori ");
        } else if (funct3 == 6) {
            // ori
            wprintw(win, "(ori ");
        } else if (funct3 == 7) {
            // andi
            wprintw(win, "(andi ");
        } else if (funct3 == 1) {
            // slli
            wprintw(win, "(slli ");
        } else if (funct3 == 5) {
            if ((imm >> 5) == 0x20) {
                // srai
                wprintw(win, "(srai ");
            } else {
                // srli
                wprintw(win, "(srli ");
            }
        } else if (funct3 == 2) {
            // slti
            wprintw(win, "(slti ");
        } else if (funct3 == 3) {
            // sltiu
            wprintw(win, "(sltiu ");
        }
        wprintw(win, "x%d x%d %d)\n", rd, rs1, imm);
    } else if (opcode == 0b0000011) {
        // I2
        uint32_t rd = (instruction >> 7) & 0b11111;
        uint32_t rs1 = (instruction >> 15) & 0b11111;
        uint32_t funct3 = (instruction >> 12) & 0b111;
        uint64_t imm = instruction >> 20;
        uint64_t m = 1U << (12 - 1);
        imm = (imm ^ m) - m;

        if (funct3 == 0) {
            // lb
            wprintw(win, "(lb ");
        } else if (funct3 == 1) {
            // lh
            wprintw(win, "(lh ");
        } else if (funct3 == 2) {
            // lw
            wprintw(win, "(lw ");
        } else if (funct3 == 3) {
            // ld
            wprintw(win, "(ld ");
        } else if (funct3 == 4) {
            // lbu
            wprintw(win, "(lbu ");
        } else if (funct3 == 5) {
            // lhu
            wprintw(win, "(lhu ");
        } else if (funct3 == 6) {
            // lwu
            wprintw(win, "(lwu ");
        }
        if (imm == 0) {
            wprintw(win, "x%d x%d)\n", rd, rs1);
        } else {
            wprintw(win, "x%d (+ x%d %d))\n", rd, rs1, imm);
        }
    } else if (opcode == 0b0100011) {
        // S
        uint32_t rs1 = (instruction >> 20) & 0b11111;
        uint32_t rd = (instruction >> 15) & 0b11111;
        uint32_t funct3 = (instruction >> 12) & 0b111;
        uint64_t imm = ((instruction >> 20) & 0xfe0) | ((instruction >> 7) & 0x1f);
        uint64_t m = 1U << (12 - 1);
        imm = (imm ^ m) - m;

        if (funct3 == 0) {
            // sb
            wprintw(win, "(sb ");
        } else if (funct3 == 1) {
            // sh
            wprintw(win, "(sh ");
        } else if (funct3 == 2) {
            // sw
            wprintw(win, "(sw ");
        } else if (funct3 == 3) {
            // sd
            wprintw(win, "(sd ");
        }
        if (imm == 0) {
            wprintw(win, "x%d x%d)\n", rd, rs1);
        } else {
            wprintw(win, "(+ x%d %d) x%d)\n", rd, imm, rs1);
        }
    } else if (opcode == 0b1100011) {
        // B
        uint32_t rs1 = (instruction >> 15) & 0b11111;
        uint32_t rs2 = (instruction >> 20) & 0b11111;
        uint32_t funct3 = (instruction >> 12) & 0b111;
        uint64_t imm = ((instruction & 0x80000000) >> 19) | ((instruction & 0x7e000000) >> 20) |
                       ((instruction & 0xf00) >> 7) | ((instruction & 0x80) << 4);
        uint64_t m = 1U << (13 - 1);
        imm = (imm ^ m) - m;
        if (funct3 == 0) {
            // beq
            wprintw(win, "(beq ");
        } else if (funct3 == 1) {
            // bne
            wprintw(win, "(bne ");
        } else if (funct3 == 4) {
            // blt
            wprintw(win, "(blt ");
        } else if (funct3 == 5) {
            // bge
            wprintw(win, "(bge ");
        } else if (funct3 == 6) {
            // bltu
            wprintw(win, "(bltu ");
        } else if (funct3 == 7) {
            // bgeu
            wprintw(win, "(bgeu ");
        }
        wprintw(win, "x%d x%d %d)\n", rs1, rs2, imm);
    } else if (opcode == 0b1101111) {
        // JAL
        uint32_t rd = (instruction >> 7) & 0b11111;
        uint64_t imm = ((instruction & 0x80000000) >> 11) | ((instruction & 0x7fe00000) >> 20) |
                       ((instruction & 0x100000) >> 9) | (instruction & 0xff000);
        uint64_t m = 1U << (21 - 1);
        imm = (imm ^ m) - m;
        wprintw(win, "(jal x%d %d)\n", rd, imm);
    } else if (opcode == 0b1100111) {
        // JALR
        uint32_t rd = (instruction >> 7) & 0b11111;
        uint64_t rs = (instruction >> 15) & 0b11111;
        uint64_t offset = instruction >> 20;
        uint64_t m = 1U << (12 - 1);
        offset = (offset ^ m) - m;
        if (offset == 0) {
            wprintw(win, "(jalr x%d x%d)\n", rd, rs);
        } else {
            wprintw(win, "(jalr x%d (+ x%d %d))\n", rd, rs, offset);
        }
    } else if (opcode == 0b0110111) {
        // LUI
        uint64_t imm = instruction >> 12;
        uint64_t m = 1U << (32 - 1);
        imm = (imm ^ m) - m;
        uint32_t rd = (instruction >> 7) & 0b11111;
        wprintw(win, "(lui x%d %d)\n", rd, imm);
    } else if (opcode == 0b0010111) {
        // AUIPC
        uint64_t imm = instruction >> 12;
        uint64_t m = 1U << (32 - 1);
        imm = (imm ^ m) - m;
        uint32_t rd = (instruction >> 7) & 0b11111;
        wprintw(win, "(auipc x%d %d)\n", rd, imm);
    } else if (opcode == 0b1110011) {
        if ((instruction & (1 << 12)) != 0) {
            wprintw(win, "(ebreak)\n");
        } else {
            wprintw(win, "(ecall)\n");
        }
    } else {
        return 1;
    }

    return 0;
}

void resize() {
    int h, w;
    getmaxyx(stdscr, h, w);
    wresize(asm_win, (h/2)-1, w);
    wresize(cli_win, h-(h/2), w);
    wrefresh(stdscr);
    move((h/2) - 1, 0);
    whline(stdscr, ACS_HLINE, w);
    wrefresh(stdscr);
}

uint32_t* asm_view_pc;

void print_asm(int cursor_x) {
    int h, w;
    getmaxyx(stdscr, h ,w);
    h = (h / 2) - 1;
    uint32_t* start = (asm_view_pc - (h / 2)) < instructions ? instructions : asm_view_pc - (h / 2);
    wmove(asm_win, 0, 0);
    for (int i = 0; i < h; i++) {
        if (pc == start) {
            wattron(asm_win, A_STANDOUT);
        }
        wprintw(asm_win, "%x\t", start);
        if (print_instruction(asm_win, start[0])) {
            wprintw(asm_win, "\n");
        }
        if (pc == start) {
            wattroff(asm_win, A_STANDOUT);
        }
        start++;
    }
    getmaxyx(stdscr, h, w);
    wmove(cli_win, h-(h/2)-1, cursor_x);
    wrefresh(asm_win);
    wrefresh(stdscr);
}

void asm_view(int cursor_x) {
    curs_set(0);
    while (1) {
        int ch = getch();
        if (ch == KEY_RESIZE) {
            resize();
        } else if (ch == ALT_J) {
            curs_set(1);
            return;
        } else if (ch == 'j') {
            asm_view_pc++;
            print_asm(cursor_x);
            wrefresh(cli_win);
        } else if (ch == 'k') {
            asm_view_pc = asm_view_pc <= instructions ? instructions : asm_view_pc - 1;
            print_asm(cursor_x);
            wrefresh(cli_win);
        }
    }
}

void prompt() {
    asm_view_pc = pc;
    print_asm(0);

prompt:
    int history_pos = history_end;
    waddstr(cli_win, "> ");
    wrefresh(cli_win);
    char buf[1024];
    buf[0] = 0;
    char* cur_item = buf;
    int size = 0;
    while (1) {
        int ch = getch();
        if (ch == KEY_RESIZE) {
            resize();
            int y, x;
            getmaxyx(cli_win, y, x);
            wmove(cli_win, y, size+2);
            wrefresh(cli_win);
        } else if ((ch == KEY_BACKSPACE) && (cur_item == buf)) {
            if (size) {
                int y, x;
                getyx(cli_win, y, x);
                mvwaddch(cli_win, y, x-1, ' ');
                wmove(cli_win, y, x-1);
                wrefresh(cli_win);
                size--;
            }
        } else if (ch == ALT_K) {
            asm_view(size+2);
            int y, x;
            getmaxyx(cli_win, y, x);
            wmove(cli_win, y, size+2);
            wrefresh(cli_win);
        } else if (ch == KEY_UP) {
            if (history_pos != history_start) {
                history_pos = history_pos == 0 ? 99 : history_pos - 1;
                cur_item = history[history_pos];
            }
            int y, x;
            getyx(cli_win, y, x);
            wmove(cli_win, y, 2);
            wclrtoeol(cli_win);
            wmove(cli_win, y, 2);
            waddstr(cli_win, cur_item);
            wrefresh(cli_win);
        } else if (ch == KEY_DOWN) {
            if (history_end == history_pos) {
                cur_item = buf;
            } else {
                history_pos = history_pos == 99 ? 0 : history_pos + 1;
                cur_item = history[history_pos];
            }
            int y, x;
            getyx(cli_win, y, x);
            wmove(cli_win, y, 2);
            wclrtoeol(cli_win);
            wmove(cli_win, y, 2);
            waddstr(cli_win, cur_item);
            wrefresh(cli_win);
        } else if (ch == '\n') {
            wechochar(cli_win, ch);
            break;
        } else if (ch == 4) {
            // CTRL-D
            wechochar(cli_win, '\n');
            goto prompt;
        } else if ((ch < 128) && (cur_item == buf)) {
            buf[size] = ch;
            buf[size+1] = 0;
            size++;
            wechochar(cli_win, ch);
        } else {
            //wprintw(cli_win, "%d\n", ch);
            //wrefresh(cli_win);
        }
    }

    if (cur_item != buf) {
        size = strlen(cur_item);
    }

    if (size == 0) {
        goto prompt;
    }

    // add to history
    char* cmd = malloc(size+1);
    memcpy(cmd, cur_item, size);
    cmd[size] = 0;
    char* old = history[history_end];
    if (old != NULL) {
        free(old);
    }
    history[history_end] = cmd;
    history_end = (history_end + 1) % 100;
    if (history_end <= history_start) {
        history_start = (history_start + 1) % 100;
    }

    if (size >= 1 && cur_item[0] == 's') {
        // step
        return;
    } else if (size == 1 && cur_item[0] == 'd') {
        wprintw(cli_win, "pc:\t0x%x\t%d\t\t", pc, pc);
        wprintw(cli_win, "x%d:\t0x%x\t%d\n", 16, registers[16], registers[16]);
        for (int i = 1; i < 16; i++) {
            wprintw(cli_win, "x%d:\t0x%x\t%d\t\t", i, registers[i], registers[i]);
            wprintw(cli_win, "x%d:\t0x%x\t%d\n", i+16, registers[i+16], registers[i+16]);
        }
        wrefresh(cli_win);
        goto prompt;
    } else if (size == 4 && strncmp(cur_item, "perf", 4) == 0) {
        // print perf
        wprintw(cli_win, "Instruction count: %d\n", perf.instruction_count);
        wprintw(cli_win, "Loads: %d\n", perf.loads);
        wprintw(cli_win, "Stores: %d\n", perf.stores);
        wprintw(cli_win, "Syscalls: %d\n", perf.syscalls);
        wprintw(cli_win, "Heap size: 0x%x %d\n", heap_end - heap_start, heap_end - heap_start);
        wrefresh(cli_win);
        goto prompt;
    } else if (size == 1 && cur_item[0] == 'i') {
        // print current instruction
        if (pc == instructions) {
            print_instruction(cli_win, pc[0]);
        } else {
            print_instruction(cli_win, (pc - 1)[0]);
        }
        wrefresh(cli_win);
        goto prompt;
    } else if (size >= 1 && cur_item[0] == 'p') {
        // print register
        goto prompt;
    } else if (size == 1 && cur_item[0] == 'r') {
        // run
        debug = 0;
        return;
    } else if (size >= 1 && cur_item[0] == 'q') {
        // quit
        // TODO: prompt
        if (curses) {
            endwin();
        }
        exit(0);
    } else {
        goto prompt;
    }
}
