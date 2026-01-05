// I have no idea what I'm doing. Just needed a simple serial driver, so you can actually type...
#![feature(trait_upcasting)]
#![no_std]
#![no_main]

#[no_link]
extern crate kernel;

use kernel::event;
use kernel::event::CallbackHook;
use kernel::event::CallbackResult;
use kernel::arch::x86::{io, idt::IntFrame};
use kernel::tty::TTY;
use kernel::println;
use kernel::sync::mutex::Mutex;

kernel::module!([]);

/// The interrupt number for COM1 (IRQ #4)
const COM1_INTERRUPT_ID: u32 = 0x24;

const PIC1_DATA: u16 = 0x21;

/// The offset of COM1 registers.
const COM1: u16 = 0x3f8;
/// The offset of COM2 registers.
const COM2: u16 = 0x2f8;
/// The offset of COM3 registers.
const COM3: u16 = 0x3e8;
/// The offset of COM4 registers.
const COM4: u16 = 0x2e8;

/// When DLAB = 0: Data register
const DATA_REG_OFF: u16 = 0;
/// When DLAB = 0: Interrupt Enable Register
const INTERRUPT_REG_OFF: u16 = 1;
/// When DLAB = 1: least significant byte of the divisor value
const DIVISOR_LO_REG_OFF: u16 = 0;
/// When DLAB = 1: most significant byte of the divisor value
const DIVISOR_HI_REG_OFF: u16 = 1;
/// Interrupt Identification and FIFO control registers
const II_FIFO_REG_OFF: u16 = 2;
/// Line Control Register
const LINE_CTRL_REG_OFF: u16 = 3;
/// Modem Control Register
const MODEM_CTRL_REG_OFF: u16 = 4;
/// Line Status Register
const LINE_STATUS_REG_OFF: u16 = 5;
/// Modem Status Register
const MODEM_STATUS_REG_OFF: u16 = 6;
/// Scratch Register
const SCRATCH_REG_OFF: u16 = 7;

fn can_read() -> bool {
    unsafe { (io::inb(COM1 + LINE_STATUS_REG_OFF) & 1) != 0 }
}

fn read_data() -> u8 {
    unsafe { io::inb(COM1) }
}

pub struct SerialHandler {
    /// The callback hook for serial input interrupts.
    interrupt_callback_hook: Option<CallbackHook>,
}


/// Global variable containing the module's instance.
static SERIAL: Mutex<SerialHandler> = Mutex::new(SerialHandler {
    interrupt_callback_hook: None,
});


fn init_in() -> Result<(), ()> {

    let mut serial = SERIAL.lock();

    let callback = |_id: u32, _code: u32, _frame: &mut IntFrame, _ring: u8| {

        while can_read() {
            let data = read_data();
            TTY.input(&[data]);
        }
        CallbackResult::Continue
    };

    let hook_result = event::register_callback(COM1_INTERRUPT_ID, callback);
    serial.interrupt_callback_hook = hook_result.map_err(|_| ())?;

    // Enable interrupts
    unsafe {
        let mask = io::inb(PIC1_DATA);
        io::outb(PIC1_DATA, mask & !(1 << 4));
        io::outb(COM1 + INTERRUPT_REG_OFF, 0x01);
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn init() -> bool {
    match init_in() {
        Ok(_) => {
            true
        }
        Err(_) => {
            println!("Failed to initialize serial module!");
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn fini() {
    SERIAL.lock().interrupt_callback_hook = None;
}

