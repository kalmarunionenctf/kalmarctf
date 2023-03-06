#![no_std]

use ps3_sys::{
    pad::{self, Pads},
    println, tiny3d,
};
use runty8_core::{Event, InputEvent, Key, KeyState, KeyboardEvent};

const FONT: &[u8] = include_bytes!("../../msxfont.bin");

const BUTTON_MAPPINGS: &[(pad::Button, Key)] = [
    (pad::Button::Cross, Key::X),
    (pad::Button::Circle, Key::C),
    (pad::Button::Square, Key::Q),
    (pad::Button::Up, Key::UpArrow),
    (pad::Button::Down, Key::DownArrow),
    (pad::Button::Right, Key::RightArrow),
    (pad::Button::Left, Key::LeftArrow),
]
.as_slice();

static ALL_BLACK: &[u32] = [0xff000000; 128 * 128].as_slice();
// static ALL_WHITE: &[u32] = [0xffffffff; 128 * 128].as_slice();

/// Create a window (or canvas, in wasm) and respond to events on it.
pub fn event_loop(mut on_event: impl FnMut(Event, &mut dyn FnMut(&[u32])) + 'static) -> ! {
    println!("Starting event loop");

    let pads = Pads::<1>::init().unwrap();

    println!("Pads initialized");

    tiny3d::initialize();

    println!("Tiny3D initialized");

    tiny3d::font::load_bitmap_font(FONT, 0, 255, 8, 8, 1, 1);
    unsafe {
        use tiny3d::font::*;
        SetFontTextureSmooth(0);
        SetFontSize(12, 12);
        SetFontColor(0xffffffff, 0x0);
        SetFontAutoCenter(0);
    }

    // let mut screen_info = ScreenInfo::new(640.0, 640.0);

    let mut tex = tiny3d::Texture::new(ALL_BLACK, 128, 128, 128 * 4);

    println!("Texture created");

    // TODO: Current system time lol
    // let mut current_time = 0;
    // let mut frame_no = 0u64;

    let mut prev_pads = pads.get_data().unwrap();

    // for (port, pad) in prev_pads.iter().enumerate() {
    //     println!("Pad @ {}: {:?}", port + 1, pad);
    // }

    let mut half_fps = false;
    let mut should_update = true;
    let mut notif = None;

    loop {
        let mut new_pads = pads.get_data().unwrap();

        for (new_pad, old_pad) in new_pads.iter_mut().zip(prev_pads.iter()) {
            match new_pad {
                Some(pad) if pad.is_invalid() => {
                    *new_pad = *old_pad;
                }
                _ => {}
            }
        }

        if new_pads != prev_pads {
            match (new_pads[0], prev_pads[0]) {
                (Some(new), Some(prev))
                    if !prev.get_button(pad::Button::Triangle)
                        && new.get_button(pad::Button::Triangle) =>
                {
                    half_fps = !half_fps;
                    should_update = true;
                    notif = Some((
                        if half_fps {
                            b"Half FPS enabled\0".as_slice()
                        } else {
                            b"Half FPS disabled\0".as_slice()
                        },
                        60,
                    ));
                }
                _ => {}
            }
            prev_pads = new_pads;
            // for (port, pad) in prev_pads.iter().enumerate() {
            //     println!("Pad @ {}: {:?}", port + 1, pad);
            // }
            if let Some(pad) = prev_pads[0] {
                for &(pad_btn, key) in BUTTON_MAPPINGS {
                    on_event(
                        Event::Input(InputEvent::Keyboard(KeyboardEvent {
                            key,
                            state: if pad.get_button(pad_btn) {
                                KeyState::Down
                            } else {
                                KeyState::Up
                            },
                        })),
                        &mut |_| {},
                    );
                }
            }
        }

        let mut draw_text = || {
            if let Some((s, t)) = notif {
                unsafe {
                    tiny3d::font::DrawString(10., 512. - 22., s.as_ptr());
                }
                if t == 1 {
                    notif = None;
                } else {
                    notif = Some((s, t - 1));
                }
            }
        };

        let draw: &mut dyn FnMut(&[u32]) = &mut |pixels| {
            tiny3d::clear_2d();

            tex.replace(pixels);
            tex.set();
            tiny3d::draw_background_tex();

            draw_text();

            tiny3d::flip();
        };

        if should_update {
            on_event(Event::Tick { delta_millis: 0.0 }, draw);
        } else {
            tiny3d::clear_2d();

            tex.set();
            tiny3d::draw_background_tex();

            draw_text();

            tiny3d::flip();
        }
        // frame_no = (frame_no + 1) % (60 * 10);
        if half_fps {
            should_update = !should_update;
        }
    }
}
