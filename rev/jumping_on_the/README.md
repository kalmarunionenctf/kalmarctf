# Jumping on the PPU/SPU
## Author: nrabulinski
## Solves: SPU - 5, PPU - 4
## Description
I found an old blu-ray disc with a game on it so I decided to dump it,
can you find anything interesting inside of it?
(If you find a flag and it doesn't work, try the other challenge!)

## Hint (PPU)
It seems like you won't reach the flag through in normal gameplay. You may need to cheat a little

## Hint (SPU)
Check out the scoreboard, it's crazy efficient!

## Other notes
### Credits
runty8, a Pico8 clone in Rust, by jjant - https://github.com/jjant/runty8  
Celeste by Maddy Thorson and Noel Berry - https://www.lexaloffle.com/bbs/?tid=2145  
miniz, a zlib-replacement library - https://github.com/richgel999/miniz

### Building
To build the project, you need a nightly Rust toolchain, `just` and `PSL1GHT`.  
Detailed instructions soon.

### Project structure
- `ppu` - Main code of the game
- `spu-c` - Code running on SPU threads
- `ppu-gcc-cargo-wrapper` - Wrapper to work around quirks with linking PPU binaries from Rust

### Code quality
The code is very much not idiomatic Rust, but it's the state in which the challenge was shipped.
A more idiomatic port, along with other crates for developing homebrew for the PS3 in Rust,
will be publicly available on my personal Github some time later this year.
