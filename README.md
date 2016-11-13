# RwxChecker #

RwxChecker is a simple tool that detects when a process requests a page with read, write, and execute permissions simultaneously. It works by overriding *mmap* and *mprotect* syscalls and prints a backtrace to assist in tracking down potentially vulnerable page allocations.

### Requirements ###

* x86_64 Linux
* [libunwind](http://www.nongnu.org/libunwind/download.html), tested with 1.1

### Compilation ###

RwxChecker must be compiled as a shared library:

```
gcc -fPIC -shared -Wall -Wextra rwx_checker.c -o librwx_checker.so -ldl -lunwind
```


### Usage ###

Preload both *libunwind.so* and *librwx_checker.so* into your executable (backtraces will be printed to stderr):

```
LD_PRELOAD="libunwind.so /path/to/librwx_checker.so" target_executable
```
