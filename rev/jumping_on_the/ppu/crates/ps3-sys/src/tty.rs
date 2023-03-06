use core::fmt::{Error as FmtError, Write};
use core::result::Result::{Err, Ok};

use crate::sys::ppu::sys::tty as tty_sys;

pub struct Tty<const CHAN: i32>;

impl<const CHAN: i32> Write for Tty<CHAN> {
    #[inline]
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe {
            let mut written = 0;
            let len = s.len().try_into().map_err(|_| FmtError)?;
            let err = tty_sys::sys_tty_write(CHAN, s.as_ptr(), len, &mut written);
            if err == 0 && written == len {
                Ok(())
            } else {
                Err(FmtError)
            }
        }
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::tty::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[doc(hidden)]
#[inline]
pub fn _print(_args: core::fmt::Arguments) {
    // TODO: Maybe don't ignore this error?
    // let _ = Tty::<0>.write_fmt(args);
}
