use core::{marker::PhantomData, mem::MaybeUninit};

use crate::sys::ppu::io::pad as pad_sys;

#[derive(Debug, Clone, Copy)]
pub struct Error;

// TODO: N can't be bigger than 7 and certainly not u32
// TODO: Wrap main() so this can't be initialized more than once at a time.
//       Similarly to uefi-rs
pub struct Pads<const N: usize> {
    _private: PhantomData<()>,
}

impl<const N: usize> Pads<N> {
    pub fn init() -> Result<Self, Error> {
        unsafe {
            // TODO: Safety here
            if pad_sys::ioPadInit(N as u32) != 0 {
                return Err(Error);
            }
        }
        Ok(Pads {
            _private: PhantomData,
        })
    }

    pub fn get_data(&self) -> Result<[Option<Pad>; N], Error> {
        let info = unsafe {
            let mut info = MaybeUninit::uninit();
            if pad_sys::ioPadGetInfo2(info.as_mut_ptr()) != 0 {
                return Err(Error);
            }
            info.assume_init()
        };
        Ok(core::array::from_fn(|port| {
            if info.port_status[port] & 1 == 1 {
                Some(unsafe {
                    let mut data = MaybeUninit::uninit();
                    if pad_sys::ioPadGetData(port as u32, data.as_mut_ptr()) != 0 {
                        panic!("ioPadGetData errored after checking pad info");
                    }
                    data.assume_init().into()
                })
            } else {
                None
            }
        }))
    }
}

impl<const N: usize> Drop for Pads<N> {
    fn drop(&mut self) {
        unsafe {
            // TODO: Abort if this fails
            let _ = pad_sys::ioPadEnd();
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Pad {
    invalid: bool,
    buttons: u16,
    // r_stick_h: u16,
    // r_stick_v: u16,
    // pub raw: pad_sys::padData,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Button {
    L2 = 0,
    R2,
    L1,
    R1,
    Triangle,
    Circle,
    Cross,
    Square,
    Select,
    L3,
    R3,
    Start,
    Up,
    Right,
    Down,
    Left,
}

impl Button {
    fn mask(self) -> u16 {
        1 << (self as u8)
    }
}

impl Pad {
    pub fn get_button(&self, btn: Button) -> bool {
        self.buttons & btn.mask() != 0
    }

    pub fn get_buttons(&self) -> u16 {
        self.buttons
    }

    pub fn is_invalid(&self) -> bool {
        self.invalid
    }
}

impl From<pad_sys::padData> for Pad {
    fn from(value: pad_sys::padData) -> Self {
        Pad {
            invalid: value.len == 0
                || value.halflen >> 4 != 7
                || value.len != ((value.halflen & 0x0f) as i32 * 2),
            buttons: (value.buttons_upper as u16) << 8 | value.buttons_lower as u16,
            // r_stick_h: value.r_stick_h,
            // r_stick_v: value.r_stick_v,
            // raw: value,
        }
    }
}
