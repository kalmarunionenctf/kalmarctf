#![no_std]
#![deny(missing_docs)]

//! Run a standalone Runty8 game natively or in wasm.

use runty8_core::{App, Event, Input, Pico8, Resources};
use runty8_event_loop::event_loop;

/// Runs a standalone Runty8 game.
pub fn run<Game: App + 'static>(resources: Resources) -> ! {
    let mut pico8 = Pico8::new(resources);
    let mut game = Game::init(&mut pico8);
    let mut input = Input::new();

    // const DELTA_TIME: f64 = 1000.0 / 30.0;

    // let mut accumulated_delta = 0.0;
    let on_event = move |event, draw: &mut dyn FnMut(&[u32])| match event {
        Event::Tick { delta_millis: _ } => {
            // accumulated_delta += delta_millis;

            // while accumulated_delta > DELTA_TIME {
            pico8.state.update_input(&input);

            game.update(&mut pico8);
            game.draw(&mut pico8);

            draw(pico8.draw_data.buffer());

            // accumulated_delta -= DELTA_TIME;
            // }
        }
        Event::Input(input_event) => {
            input.on_event(input_event);
        }
        Event::WindowClosed => {
            // *control_flow = ControlFlow::Exit;
        }
    };

    event_loop(on_event);
}
