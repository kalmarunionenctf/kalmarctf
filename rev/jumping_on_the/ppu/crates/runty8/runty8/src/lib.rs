#![no_std]

//! Entrypoints for all games using runty8.

#[doc(inline)]
pub use runty8_core::{flr, load_assets, mid, rnd, sin, App, Button, Pico8};

use runty8_core::Resources;

pub fn run<Game: App + 'static>(resources: Resources) -> ! {
    runty8_runtime::run::<Game>(resources)
}
