# Solutions
## Author solution
To get the exploit out of `/dev/sda` which is non-readable, you could create a new device node with `mknod exp b 8 0`, which would be created as your user and thus readable.

There were many ways to solve the second part. One interesting way, is to set the direction bit which flips all x86 string operations around (See `swedish_memcpy` from KalmarCTF 2023). When handling syscalls, the direction bit is not cleared. This will cause a `memset` operation to fill the stack with nullbytes, which in turn makes the kernel return to NULL. We can then allocate the zero-page as executable to take control of the kernel instruction pointer. This cannot be done with mmap, because there's a check, but it can be done using the ELF parser in the kernel.

Another way was to overwrite kernel memory using mmap, which will happily unmap kernel memory and place your pages there instead. Since there's no SMEP or SMAP, this is no problem, and you can get kernel instruction pointer control.

## Solution by @khokho
* mount `/dev/sda` to `~/mnt`
* open `~/mnt/somefile`
* umount `~/mnt`
* mount `tmpfs` on `~/mnt`
* the open fd has a inode from `/dev/sda` but will read from the `tmpfs` where flag is stored
so just open many files until you hit the same inode as flag has on tmpfs
