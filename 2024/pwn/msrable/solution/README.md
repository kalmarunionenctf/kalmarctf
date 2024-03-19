# Solutions
## Author solution
You can read and write from `/dev/cpu/0/msr`, which allows us to overwrite MSRs. 

We can start by leaking the kernel base with `MSR_LSTAR`, which points to the syscall entrypoint. We can then change `MSR_FMASK` to not clear the `AC` flag on `syscall`, which allows us to ROP on the userspace stack.

Page-table isolation is enabled, but there's of course a gadget to enable the kernel pages within the stub placed at `paranoid_entry+69`, which we then change `MSR_LSTAR` to. This gadget ends in a `ret`, which allows us to ROP.

There are many ways to escalate privileges from here. The simplest is just calling `prepare_kernel_cred`, returning to userspace, then calling `commit_creds`, resetting `MSR_LSTAR` and returning to userspace.
