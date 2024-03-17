use std::{env::args_os, io, os::unix::process::CommandExt, process::Command};

fn main() -> io::Result<()> {
    let mut args = Vec::new();
    let mut nodefaultlibs = false;
    let mut lrt = false;
    let mut lc = false;
    let mut lsysbase = false;
    let mut llv2 = false;

    for arg in args_os().skip(1) {
        match arg.to_str() {
            Some("-nodefaultlibs") => nodefaultlibs = true,
            Some("-lrt") => lrt = true,
            Some("-lc") => lc = true,
            Some("-lsysbase") => lsysbase = true,
            Some("-llv2") => llv2 = true,
            // TODO: Remove once libc crate is patched
            Some(
                "-lpthread" | "-lutil" | "-lexecinfo" | "-lmemstat" | "-lkvm" | "-lprocstat"
                | "-ldevstat",
            ) => (),
            _ => args.push(arg),
        }
    }

    if nodefaultlibs {
        args.extend(lrt.then(|| "-lrt".into()));
        args.extend(lc.then(|| "-lc".into()));
        args.extend(lsysbase.then(|| "-lsysbase".into()));
        args.extend(llv2.then(|| "-llv2".into()));
    }

    Err(Command::new("ppu-gcc").args(args).exec())
}
