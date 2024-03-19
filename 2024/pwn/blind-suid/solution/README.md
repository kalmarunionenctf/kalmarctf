# Solutions
## Author solution
If you ptrace ./minisudo, the setuid bit is ignored and the process is run as your user. You can now extract information from the process, which for example can be seen by running
```bash
strace ./minisudo
```
Notably, though is that we cannot use PEEKTEXT or POKETEXT, because of the read restriction on the executable file. But there are no limits to reading and writing to registers.
Since it's a dynamically linked executable, we know that the process starts up inside of `/lib64/ld-linux-x86-64.so.2`, which we can extract from the remote.
Looking around for gadgets, we could for example use the following for leaking memory:
```
   0x7ffff7fe3308:	mov    rdi,QWORD PTR [rdi]
```
The final attack can be seen in `extract.c`.
We then get a binary, that we have to reverse, but this is pretty trivial and was only there to ensure that players have to extract the binary.


## Solution by @pitust

> You can either use ptrace, or the `PR_SET_NO_NEW_PRIVS` prctl to prevent the target from being affected by setuid. It is then trivial to use `LD_PRELOAD` (possibly in combination with `personality(ADDR_NO_RANDOMIZE)`) to dump the binary.
