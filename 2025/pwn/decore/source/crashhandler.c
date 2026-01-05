#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <elf.h>
#include <sys/procfs.h>  // prpsinfo_t
#include <signal.h>      // siginfo_t
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <errno.h>


typedef struct {
    long count;
    long page_size;
    struct {
        long start;
        long end;
        long file_ofs;
    } elem[0];
} note_files_t;


typedef struct {
    Elf64_Sym *symtab;
    const char *strtab;
    size_t count;
} symbols_t;

typedef struct file_map_struct file_map;
struct file_map_struct {
    const char *path;
    file_map *next;
    int fd;
    int symtabcnt;
    long base;
    symbols_t symbols[2];
};


#define MAX_THREADS 32

note_files_t *note_files = NULL;
file_map **filemaps = NULL;

siginfo_t *siginfo = NULL;
struct user_regs_struct *regs[MAX_THREADS] = { };
int thread_count = 0;


const char *get_symbol_name(long target, long *res) {
    void *map;
    Elf64_Ehdr* ehdr;
    Elf64_Shdr* shdr;
    file_map *filemap = NULL;

    if (!note_files) {
        return NULL;
    }


    for (int i = 0; i < note_files->count; i++) {
        if (note_files->elem[i].start <= target && target <= note_files->elem[i].end) {
            filemap = filemaps[i];
            break;
        }
    }
    if (filemap == NULL) {
        return NULL;
    }
    //fprintf(out, "filemap{fd=%d, base=0x%lx}\n", filemap->fd, filemap->base);

    if (!filemap->symtabcnt) {
        size_t file_size = lseek(filemap->fd, 0, SEEK_END);
        map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, filemap->fd, 0);
        if (map == MAP_FAILED) {
            return NULL;
        }


        ehdr = (Elf64_Ehdr*)map;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
            return NULL;
        }

        if (ehdr->e_type == ET_EXEC) {
            filemap->base = 0;  // no PIE, so we don't need to offset with base
        }

        shdr = (Elf64_Shdr*)(map + ehdr->e_shoff);

        // Iterate through section headers to find the symbol table and string table
        for (int i = 0; i < ehdr->e_shnum; i++) {
            //printf("shdr[%d].sh_type = %d\n", i, shdr[i].sh_type);
            if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
                filemap->symbols[filemap->symtabcnt] = (symbols_t) {
                    .symtab = (Elf64_Sym*)((char*)map + shdr[i].sh_offset),
                    .strtab = (const char*)map + shdr[shdr[i].sh_link].sh_offset,
                    .count = shdr[i].sh_size / sizeof(Elf64_Sym),
                };
                filemap->symtabcnt++;
                if (filemap->symtabcnt == 2)
                    break;
            }
        }
    }

    // Search for the closest symbol in both symbol tables
    const char *best_symbol = NULL;
    long best = 0;
    for (int idx = 0; idx < filemap->symtabcnt; idx++) {
        symbols_t *symbols = &filemap->symbols[idx];

        for (size_t i = 0; i < symbols->count; i++) {

            const char *symbol = &symbols->strtab[symbols->symtab[i].st_name];
            long address = symbols->symtab[i].st_value;

            if (ELF64_ST_TYPE(symbols->symtab[i].st_info) != STT_FUNC) {
                continue;
            }
            if (symbol[0] == 0 || address == 0) {
                continue;
            }
            address += filemap->base;

            // Find closest. This involves going through the entire list!
            if (target >= address && address > best) {
                best = address;
                best_symbol = symbol;
            }


        }
    }

    if (best) {
        *res = best;
    }
    return best_symbol;
}

file_map *check_exists(file_map *filemap, const char *path) {
    while (filemap) {
        if (strcmp(path, filemap->path) == 0) {
            return filemap;
        }
        filemap = filemap->next;
    }
    return NULL;
}


void copy_file(FILE *destination, FILE *source) {
    char buffer[0x1000];

    if (!source || !destination) {
        return;
    }

    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), source)) > 0) {
        size_t bytesWritten = fwrite(buffer, 1, bytesRead, destination);
        if (bytesWritten != bytesRead) {
            perror("Write error");
            return;
        }
    }

    if (ferror(source)) {
        perror("Read error");
    }
}



int main (int argc, char *argv[]) {
    Elf64_Ehdr ehdr = { };
    Elf64_Phdr *phdrs = NULL;
    Elf64_Nhdr *note = NULL;
    //char *note_name = NULL;
    void *note_desc = NULL;
    char path[0x100];
    
    if (argc < 2) {
        fprintf(stderr, "Not enough arguments\n");
        exit(1);
    }
    
    if (fread(&ehdr, sizeof(ehdr), 1, stdin) != 1) exit(1);
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file\n");
        exit(1);
    }

    phdrs = calloc(ehdr.e_phnum, sizeof(*phdrs));
    if (!phdrs) exit(-ENOMEM);
    if (fread(phdrs, sizeof(*phdrs), ehdr.e_phnum, stdin) != ehdr.e_phnum) exit(1);
    
    /*for (int i = 0; i < ehdr.e_phnum; i++) { // TODO: REMOVE
        fprintf(out, "%016lx-%016lx (0x%lx) (0x%lx)\n", phdrs[i].p_vaddr, phdrs[i].p_vaddr+phdrs[i].p_memsz, phdrs[i].p_memsz, phdrs[i].p_filesz);
    }*/

    if (phdrs[0].p_type != PT_NOTE) {
        exit(1);
    }
    char *notes = malloc(phdrs[0].p_filesz);
    if (!notes) exit(-ENOMEM);
    if (fread(notes, sizeof(char), phdrs[0].p_filesz, stdin) != phdrs[0].p_filesz) exit(1);

    for (off_t off = 0; off < phdrs[0].p_filesz;) {
        note = (Elf64_Nhdr*)&notes[off];
        off += sizeof(Elf64_Nhdr);
        //note_name = &notes[off];
        off += (note->n_namesz + 3) & ~0x3;
        note_desc = &notes[off];
        off += (note->n_descsz + 3) & ~0x3;

        //printf("type=%x namesz=%d descsz=%d\n", note->n_type, note->n_namesz, note->n_descsz);

        switch (note->n_type) {
            case NT_PRSTATUS: {
                if (thread_count >= MAX_THREADS) break;
                regs[thread_count++] = note_desc + offsetof(prstatus_t, pr_reg);
                //printf("rax=%llx, rip=%llx\n", regs->rax, regs->rip);
                break;
            }

            case NT_SIGINFO: {
                siginfo = note_desc;
                //printf("fault addr: %p\n", siginfo->si_addr);
                break;
            }

            case NT_FILE: {
                note_files = note_desc;

                filemaps = calloc(note_files->count, sizeof(filemaps[0]));
                if (!filemaps) exit(-ENOMEM);

                char *ptr = (char*)&note_files->elem[note_files->count];
                file_map *map_list = NULL;

                file_map *curr_map = NULL;
                for (int i = 0; i < note_files->count; i++, ptr += strlen(ptr) + 1) {
                    //fprintf(out, "%016lx-%016lx %s\n", note_files->elem[i].start, note_files->elem[i].end, ptr);
                    if (curr_map = check_exists(map_list, ptr)) {
                        filemaps[i] = curr_map;
                        curr_map->base = MIN(curr_map->base, note_files->elem[i].start);
                        continue;
                    }

                    int fd = open(ptr, O_RDONLY);
                    if (fd == -1) {
                        filemaps[i] = NULL;
                        continue;
                    }
                    curr_map = calloc(1, sizeof(*curr_map));
                    if (!curr_map) exit(-ENOMEM);
                    curr_map->path = ptr;
                    curr_map->fd = fd;
                    curr_map->base = note_files->elem[i].start;
                    curr_map->next = map_list;
                    map_list = curr_map;
                    //printf("%s = %d\n", ptr, curr_map->fd);
                    filemaps[i] = curr_map;
                }
                break;
            }
        }
    }

    FILE *out = fopen("/var/log/crash.log", "a+");
    if (!out) {
        fprintf(stderr, "Could not open log file: %s\n", strerror(errno));
        exit(errno);
    }
    
    fprintf(out, "Process (pid=%s) crashed on %p\n", argv[1], siginfo->si_addr);

    for (int i = 0; i < thread_count; i++) {
        long target = regs[i]->rip;
        long symbol_addr;
        const char *symbol = get_symbol_name(target, &symbol_addr);
        if (symbol) {
            fprintf(out, "- Thread %d: 0x%lx (%s+%ld)\n", i, target, symbol, target-symbol_addr);
        } else {
            fprintf(out, "- Thread %d: 0x%lx\n", i, target);
        }
    }
    
    fprintf(out, "\n");
    fclose(out);

    snprintf(path, sizeof(path), "/var/crash/core.%s", argv[1]);
    out = fopen(path, "w+");
    if (!out) {
        fprintf(stderr, "Could not create core file: %s\n", strerror(errno));
        exit(errno);
    }
    fwrite(&ehdr, sizeof(ehdr), 1, out);
    fwrite(phdrs, sizeof(*phdrs), ehdr.e_phnum, out);
    fwrite(notes, sizeof(char), phdrs[0].p_filesz, out);
    copy_file(out, stdin);
    fclose(out);    
    return 0;
}
