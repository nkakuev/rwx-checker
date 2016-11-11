#define UNW_LOCAL_ONLY
#define _GNU_SOURCE

#include <dlfcn.h>
#include <libunwind.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

void show_backtrace (void)
{
  unw_cursor_t cursor; unw_context_t uc;
  unw_word_t ip, sp, offp;
  char symbol[4096];

  unw_getcontext(&uc);
  unw_init_local(&cursor, &uc);

  while (unw_step(&cursor) > 0)
  {
    unw_get_reg(&cursor, UNW_REG_IP, &ip);
    unw_get_reg(&cursor, UNW_REG_SP, &sp);

    if (unw_get_proc_name(&cursor, symbol, sizeof(symbol), &offp) < 0)
    {
        sprintf(symbol, "%s", "????");
    }

    printf ("0x%lx\tin %s (ip = %lx, sp = %lx)\n",
            offp, symbol, (long) ip, (long) sp);
  }
}

void check_memory_protection(void *addr, int prot)
{
    if (prot & PROT_EXEC && prot & PROT_READ && prot & PROT_WRITE)
    {
        fprintf(stderr, "An rwx page requested at address %p\n", addr);
        fprintf(stderr, "Backtrace:\n");

        show_backtrace();
    }
}

void assert_symbol_address(void *addr)
{
    if (!addr)
    {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }
}

void *mmap(void *addr, size_t length, int prot, int flags,
                          int fd, off_t offset)
{
    check_memory_protection(addr, prot);

    void *(*next_mmap)(void *addr, size_t length, int prot, int flags,
                       int fd, off_t offset) = dlsym(RTLD_NEXT, "mmap");
    assert_symbol_address(next_mmap);
    return next_mmap(addr, length, prot, flags, fd, offset);
}

int mprotect(void *addr, size_t len, int prot)
{
    check_memory_protection(addr, prot);

    int (*next_mprotect)(void *addr, size_t len, int prot)
        = dlsym(RTLD_NEXT, "mprotect");
    assert_symbol_address(next_mprotect);
    return next_mprotect(addr, len, prot);
}

