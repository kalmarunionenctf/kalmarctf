#![allow(non_camel_case_types)]

use core::arch::asm;

macro_rules! sc_impl {
    ($val:literal;) => {
        let mut res: i32;
        core::arch::asm! {
            "sc",
            in("r11") $val,
            lateout("r3") res,
        };
        res
    };
    ($val:literal; $a:expr) => {
        let mut res: i32;
        core::arch::asm! {
            "sc",
            in("r3") $a,
            in("r11") $val,
            lateout("r3") res,
        };
        res
    };
    ($val:literal; $a:expr, $b:expr) => {
        let mut res: i32;
        core::arch::asm! {
            "sc",
            in("r3") $a,
            in("r4") $b,
            in("r11") $val,
            lateout("r3") res,
        };
        res
    };
    ($val:literal; $a:expr, $b:expr, $c:expr) => {
        let mut res: i32;
        core::arch::asm! {
            "sc",
            in("r3") $a,
            in("r4") $b,
            in("r5") $c,
            in("r11") $val,
            lateout("r3") res,
        };
        res
    };
    ($val:literal; $a:expr, $b:expr, $c:expr, $d:expr) => {
        let mut res: i32;
        core::arch::asm! {
            "sc",
            in("r3") $a,
            in("r4") $b,
            in("r5") $c,
            in("r6") $d,
            in("r11") $val,
            lateout("r3") res,
        };
        res
    };
    ($val:literal; $a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => {
        let mut res: i32;
        core::arch::asm! {
            "sc",
            in("r3") $a,
            in("r4") $b,
            in("r5") $c,
            in("r6") $d,
            in("r7") $e,
            in("r11") $val,
            lateout("r3") res,
        };
        res
    };
    ($val:literal; $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr) => {
        let mut res: i32;
        core::arch::asm! {
            "sc",
            in("r3") $a,
            in("r4") $b,
            in("r5") $c,
            in("r6") $d,
            in("r7") $e,
            in("r8") $f,
            in("r11") $val,
            lateout("r3") res,
        };
        res
    };
    ($val:literal; $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr) => {
        let mut res: i32;
        core::arch::asm! {
            "sc",
            in("r3") $a,
            in("r4") $b,
            in("r5") $c,
            in("r6") $d,
            in("r7") $e,
            in("r8") $f,
            in("r9") $g,
            in("r11") $val,
            lateout("r3") res,
        };
        res
    };
}

// TODO: Register clobbering (it's probably fine but better safe than sorry or something)
// TODO: Syscalls can clobber registers. Should investigate
macro_rules! lv2syscall {
    ($v:vis $name:ident = $val:literal $(: $($arg:ident : $typ:ty),+ $(,)?)?) => {
        /// # Safety
        /// Refer to documentation of said syscall for guarantees
        /// TODO: Document syscalls
        #[inline(always)]
        $v unsafe fn $name ($($($arg : $typ),+)?) -> i32 {
            sc_impl! { $val; $($($arg),+)? }
        }
    };
}

#[inline(always)]
unsafe fn write32(addr: *mut u32, value: u32) {
    asm! {
        "stw {val},0({addr})",
        "eieio",
        val = in(reg) value,
        addr = in(reg) addr,
    }
}

pub mod ppu {
    pub mod io {
        pub mod pad {
            pub const MAX_PORT_NUM: usize = 7;
            pub const MAX_PADS: usize = 127;

            #[repr(C)]
            pub struct padInfo {
                /// max pads allowed to connect
                pub max: u32,
                /// how many pads connected
                pub connected: u32,
                /// bit 0 lets the system intercept pad? other bits are reserved
                pub info: u32,
                /// array of vendor ids
                pub vendor_id: [u16; MAX_PADS],
                /// array of product ids
                pub product_id: [u16; MAX_PADS],
                /// array of pad statuses
                pub status: [u16; MAX_PADS],
            }

            #[repr(C)]
            pub struct padInfo2 {
                /// max pads allowed to connect
                pub max: u32,
                /// how many pads connected
                pub connected: u32,
                /// Bit 0 lets the system intercept pad? other bits are reserved.
                pub info: u32,
                /// Bit 0: Connected (0: Disconnected, 1: Connected), Bit 1: assign changes?
                pub port_status: [u32; MAX_PORT_NUM],
                /// Bit 1: Pressure sensitivity turned on, Bit 2: Sensors turned on.
                pub port_setting: [u32; MAX_PORT_NUM],
                /// See: PadCapabilityInfo. Bit 0: PS3SPEC, Bit 1: has_pressure, Bit 2: has_sensor, Bit 3: has_hps, Bit 4: has_vibrate.
                pub device_capability: [u32; MAX_PORT_NUM],
                /// 0: Standard, 4: Bluray Remote, 5: LDD
                pub device_type: [u32; MAX_PORT_NUM],
            }

            #[repr(C, packed)]
            pub struct padData {
                pub len: i32,
                _zeroes: u16,
                _reserved: u8,
                /// Upper half always 0x7, lower - len / 2
                pub halflen: u8,
                _more_reserved: u8,
                /// Button bitmask
                pub buttons_upper: u8,
                _buttons_gap: u8,
                pub buttons_lower: u8,
                // Analog sticks
                pub r_stick_h: u16,
                pub r_stick_v: u16,
                pub l_stick_h: u16,
                pub l_stick_v: u16,
                // Button pressure
                pub r_arrow_press: u16,
                pub l_arrow_press: u16,
                pub u_arrow_press: u16,
                pub d_arrow_press: u16,
                pub tri_press: u16,
                pub circ_press: u16,
                pub x_press: u16,
                pub sq_press: u16,
                pub l1_press: u16,
                pub r1_press: u16,
                pub l2_press: u16,
                pub r2_press: u16,
                // Gyro
                pub sens_x: u16,
                pub sens_y: u16,
                pub sens_z: u16,
                pub sens_g: u16,
                // Misc
                pub bdlen: u16,
                pub bdcode: u16,
                _even_more_reserved: [u8; 76],
            }

            #[link(name = "io")]
            extern "C" {
                #[must_use = "This function can return an error"]
                pub fn ioPadInit(max: u32) -> i32;
                #[must_use = "This function can return an error"]
                pub fn ioPadGetInfo(info: *mut padInfo) -> i32;
                #[must_use = "This function can return an error"]
                pub fn ioPadGetInfo2(info: *mut padInfo2) -> i32;
                #[must_use = "This function can return an error"]
                pub fn ioPadGetData(port: u32, data: *mut padData) -> i32;
                #[must_use = "This function can return an error"]
                pub fn ioPadEnd() -> i32;
            }
        }
    }

    pub mod lv2 {
        pub mod spu {
            use crate::sys::ppu::ppu_types::*;
            use libc::c_void;

            #[derive(Debug)]
            #[repr(C)]
            pub struct sysSpuImage {
                pub typ: u32,
                pub entryPoint: u32,
                pub segments: u32,
                pub segmentCount: u32,
            }

            #[link(name = "lv2")]
            extern "C" {
                #[must_use = "This function can return an error"]
                pub fn sysSpuImageImport(image: *mut sysSpuImage, elf: *const u8, typ: u32) -> i32;
                #[must_use = "This function can return an error"]
                pub fn sysSpuPrintfInitialize(prio: i32, entry: *const c_void) -> i32;
                #[must_use = "This function can return an error"]
                pub fn sysSpuPrintfAttachGroup(group: sys_spu_group_t) -> i32;
                #[must_use = "This function can return an error"]
                pub fn sysSpuRawImageLoad(spu: sys_raw_spu_t, image: *const sysSpuImage) -> i32;
                #[must_use = "This function can return an error"]
                pub fn sysSpuPrintfAttachThread(thread: sys_spu_thread_t) -> i32;
            }
        }

        pub mod systime {
            #[link(name = "lv2")]
            extern "C" {
                pub fn sysGetSystemTime() -> i64;
            }
        }
    }

    pub mod ppu_types {
        pub type sys_mem_id_t = u32;
        pub type sys_mem_container_t = u32;
        pub type sys_mem_addr_t = u32;

        pub type sys_raw_spu_t = u32;
        pub type sys_spu_group_t = u32;
        pub type sys_spu_thread_t = u32;

        pub type sys_ipc_key_t = u64;

        pub type sys_event_queue_t = u32;
        pub type sys_event_port_t = u32;
    }

    pub mod sys {
        pub mod event_queue {
            use crate::sys::ppu::ppu_types::*;

            /// Event queue type PPU
            pub const SYS_EVENT_QUEUE_PPU: u32 = 0x01;
            /// Event queue type SPU
            pub const SYS_EVENT_QUEUE_SPU: u32 = 0x02;

            /// Synchronize event queue FIFO
            pub const SYS_EVENT_QUEUE_FIFO: u32 = 0x01;
            /// Synchronize event queue PRIO
            pub const SYS_EVENT_QUEUE_PRIO: u32 = 0x02;
            /// Synchronize event queue PRIO_INHERIT
            pub const SYS_EVENT_QUEUE_PRIO_INHERIT: u32 = 0x03;

            /// Event port type LOCAL
            pub const SYS_EVENT_PORT_LOCAL: u32 = 0x01;

            /// Used to auto create a port name
            pub const SYS_EVENT_PORT_NO_NAME: u32 = 0x00;

            /// Used to auto create a event queue key.
            pub const SYS_EVENT_QUEUE_KEY_LOCAL: u64 = 0x00;

            /// Force destruction of event queue.
            pub const SYS_EVENT_QUEUE_FORCE_DESTROY: u32 = 0x01;

            pub const MAX_QUEUE_SIZE: i32 = 127;

            #[repr(C)]
            pub struct sys_event_t {
                /// id of emitting source
                pub source: u64,
                pub data1: u64,
                pub data2: u64,
                pub data3: u64,
            }

            #[repr(C)]
            pub struct sys_event_queue_attr_t {
                pub proto: u32,
                pub typ: u32,
                pub name: [u8; 8],
            }

            lv2syscall! {
                pub sys_event_queue_create = 128:
                event_q: *mut sys_event_queue_t,
                attr: *const sys_event_queue_attr_t,
                key: sys_ipc_key_t,
                size: i32,
            }

            lv2syscall! {
                pub sys_event_port_create = 134:
                port: *mut sys_event_port_t,
                port_type: u32,
                name: u64,
            }

            lv2syscall! {
                pub sys_event_port_connect_local = 136:
                port: sys_event_port_t,
                event_q: sys_event_queue_t,
            }

            lv2syscall! {
                pub sys_event_port_send = 138:
                port: sys_event_port_t,
                data0: u64,
                data1: u64,
                data2: u64,
            }

            #[doc = " # Safety"]
            #[doc = " Refer to documentation of said syscall for guarantees"]
            #[doc = " TODO: Document syscalls"]
            #[inline(always)]
            pub unsafe fn sys_event_queue_receive(
                event_q: sys_event_queue_t,
                event: *mut sys_event_t,
                timeout_usec: u64,
            ) -> i32 {
                let mut res: i32;
                let ev_ref = &mut *event;
                core::arch::asm! {
                    "sc",
                    in("r3") event_q,
                    in("r4") event,
                    in("r5") timeout_usec,
                    in("r11") 130,
                    lateout("r3") res,
                    lateout("r4") ev_ref.source,
                    lateout("r5") ev_ref.data1,
                    lateout("r6") ev_ref.data2,
                    lateout("r7") ev_ref.data3,
                };
                res
            }
        }

        pub mod memory {
            use crate::sys::ppu::ppu_types::*;

            pub const SYS_MEMORY_PAGE_SIZE_1M: u64 = 0x0000000000000400;
            pub const SYS_MEMORY_PAGE_SIZE_64K: u64 = 0x0000000000000200;
            pub const SYS_MEMORY_ACCESS_RIGHT_PPU_THR: u64 = 0x0000000000000008;
            pub const SYS_MEMORY_ACCESS_RIGHT_HANDLER: u64 = 0x0000000000000004;
            pub const SYS_MEMORY_ACCESS_RIGHT_SPU_THR: u64 = 0x0000000000000002;
            pub const SYS_MEMORY_ACCESS_RIGHT_RAW_SPU: u64 = 0x0000000000000001;
            pub const SYS_MEMORY_ACCESS_RIGHT_ANY: u64 = 0
                | SYS_MEMORY_ACCESS_RIGHT_PPU_THR
                | SYS_MEMORY_ACCESS_RIGHT_HANDLER
                | SYS_MEMORY_ACCESS_RIGHT_SPU_THR
                | SYS_MEMORY_ACCESS_RIGHT_RAW_SPU;
            pub const SYS_MEMORY_ACCESS_RIGHT_NONE: u64 = 0x00000000000000f0;
            pub const SYS_MEMORY_PROT_READ_ONLY: u64 = 0x0000000000080000;
            pub const SYS_MEMORY_PROT_READ_WRITE: u64 = 0x0000000000040000;
            pub const SYS_MMAPPER_NO_SHM_KEY: u64 = 0xffff000000000000;

            lv2syscall! {
                pub sys_memory_allocate = 348:
                size: usize,
                flags: u64,
                alloc_addr: *mut sys_mem_addr_t,
            }

            lv2syscall! { pub sys_memory_free = 349: start_addr: sys_mem_addr_t }

            lv2syscall! {
                pub sys_mmapper_allocate_address = 330:
                size: usize,
                flags: u64,
                align: usize,
                alloc_addr: *mut sys_mem_addr_t,
            }

            lv2syscall! {
                pub sys_mmapper_allocate_shared_memory = 332:
                shmem_key: u64,
                size: usize,
                align: usize,
                mem_id: *mut sys_mem_id_t,
            }

            lv2syscall! {
                pub sys_mmapper_search_and_map = 337:
                start_addr: sys_mem_addr_t,
                mem_id: sys_mem_id_t,
                flags: u64,
                alloc_addr: *mut sys_mem_addr_t,
            }
        }

        pub mod spu {
            use crate::sys::{
                ppu::{lv2::spu::sysSpuImage, ppu_types::*},
                write32,
            };

            pub const SPU_THREAD_EVENT_USER: u32 = 0x1;

            #[repr(C)]
            pub struct sysSpuThreadGroupAttribute {
                pub nsize: u32,
                pub name: u32,
                pub typ: u32,
                pub ct: sys_mem_container_t,
            }

            #[repr(C)]
            pub struct sysSpuThreadAttribute {
                /// C-style string for the thread's name.
                ///
                /// It's a u32 because some pointers are 4-byte wide.
                pub name: u32,
                pub nsize: u32,
                pub option: u32,
            }

            #[repr(C)]
            pub struct sysSpuThreadArgument {
                pub args: [u64; 4],
            }

            lv2syscall! {
                pub sys_spu_raw_create = 160:
                spu: *mut sys_raw_spu_t,
                attrs: *const u32,
            }

            lv2syscall! {
                pub sys_spu_initialize = 169:
                spus: u32,
                rawspus: u32,
            }

            lv2syscall! {
                pub sys_spu_thread_group_create = 170:
                group: *mut sys_spu_group_t,
                num: u32,
                prio: u32,
                attr: *const sysSpuThreadGroupAttribute,
            }

            lv2syscall! {
                pub sys_spu_thread_initialize = 172:
                thread: *mut sys_spu_thread_t,
                group: sys_spu_group_t,
                spu: u32,
                image: *const sysSpuImage,
                attributes: *const sysSpuThreadAttribute,
                arguments: *const sysSpuThreadArgument,
            }

            lv2syscall! {
                pub sys_spu_thread_group_start = 173:
                group: sys_spu_group_t,
            }

            lv2syscall! {
                pub sys_spu_thread_set_configuration = 187:
                thread: sys_spu_thread_t,
                value: u64,
            }

            lv2syscall! {
                pub sys_spu_thread_write_local_storage = 181:
                thread: sys_spu_thread_t,
                address: u32,
                value: u64,
                typ: u32,
            }

            lv2syscall! {
                pub sys_spu_thread_connect_event = 191:
                thread: sys_spu_thread_t,
                queue: sys_event_queue_t,
                typ: u32,
                spup: u8,
            }

            lv2syscall! {
                pub sys_spu_thread_bind_queue = 193:
                thread: sys_spu_thread_t,
                queue: sys_event_queue_t,
                spuq: u8,
            }

            #[inline(always)]
            fn spu_raw_get_problem_storage(spu: sys_raw_spu_t, reg: u32) -> *mut u32 {
                const BASE: *mut u8 = 0xe0000000 as *mut u8;
                const OFFSET: usize = 0x00100000;
                const PROBLEM_OFFSET: usize = 0x00040000;
                unsafe {
                    let base = BASE.add(OFFSET * spu as usize);
                    base.add(PROBLEM_OFFSET + reg as usize).cast()
                }
            }

            pub unsafe fn sys_spu_raw_write_problem_storage(
                spu: sys_raw_spu_t,
                reg: u32,
                value: u32,
            ) {
                let ptr = spu_raw_get_problem_storage(spu, reg);
                crate::println!("Writing to problem storage: {ptr:p}");
                write32(ptr, value);
            }
        }

        pub mod time {
            // TODO: Return nanoseconds as well
            #[inline]
            pub fn get_current_time() -> u64 {
                let mut secs = 0;
                let mut _nsecs = 0;

                unsafe {
                    sys_get_current_time(&mut secs, &mut _nsecs);
                }

                secs
            }

            lv2syscall! { sys_get_current_time = 145: secs: *mut u64, nsecs: *mut u64 }
        }

        pub mod tty {
            lv2syscall! {
                pub sys_tty_write = 403:
                chan: i32,
                ptr: *const u8,
                len: u32,
                written: *mut u32,
            }

            lv2syscall! {
                pub sys_tty_read = 402:
                chan: i32,
                ptr: *mut u8,
                len: u32,
                read: *mut u32,
            }
        }
    }
}
