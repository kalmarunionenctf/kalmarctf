# short circuit

**Author**: Astrid  
**Flag**: `kalmar{n3v3r_f1u5h_y0ur_NaNs_d0wn_th3_dr41n}`  

## Setup
The challenge generates a 12-word seed phrase from the [BIP39 word list](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt) using `Math.random()`, and asks the user to guess it. As a hint, the challenge provides the first letter of the first 5 words.

With 2048 words, there's `log2(2048^12)` = 132 bits of entropy (I believe the real BIP39 spec includes some sort of checksum, but we're not). The hint provides `log2(26^5)` ≈ 23.5 bits of entropy (assuming a uniform distribution, which there probably isn't). Either way, it's astronomically unlikely you'll guess the right seed phrase randomly just based on the hint.

Even if you know that `Math.random()` is cryptographically insecure, you still need at least 128 known bits to solve for the internal RNG state in the first place. There's simply too many possible states that result in the output you get for it to be feasible to guess.

So this challenge is impossible... right?

## Node 10
If you look closely at the provided Dockerfile, you'll see that it uses the image `node:10-alpine`. Node.js 10 was released in [April 2018](https://nodejs.org/en/blog/release/v10.0.0), and the v10 release went end-of-life in [May 2020](https://endoflife.date/nodejs), with the last security release (v10.24.1, the one in the Docker image) releasing in [April 2021](https://nodejs.org/en/blog/release/v10.24.1). This is a suspiciously *old* version of Node.js! Perhaps the random number generator was (even more) broken back then?

If you analyze the output of Math.random(), or search the Chromium bug tracker hard enough, you'll stumble upon [issue #42211416: "Math.random() returns biased results due to states being flushed to NAN, and after ~10s a totally fixed sequence"](https://issues.chromium.org/issues/42211416). The issue description explains it better than I could:

> The current Math.random() implementation is biased initially and then returns a fixed sequence. Internally math.random() uses xorshift128+, which has a 64 long array to store its internal data, where the last two elements in the array are the seeds. This array is composed of boxed (? I'm unsure of the terminology here) doubles. To store the two uint64_t seeds in the array, each seed is reinterpret_cast'ed as doubles before being stored into the array
> 
> Because the array is an array of boxed doubles, each double is checked for being nan before being set into the array. If it *is* any kind of nan, its set to the canonical nan representation before being stored
> 
> This is a problem because it means that if either seed in the array reinterpreted as a double is NAN in that format, it gets set to just the one NAN representation. This means in practice, it is relatively common (1/50000 occurance in testing, but whatever the probability is that any of the two seeds is nan / 62) that a range of seeds are flushed to a specific known value, which makes the generator probably biased as nearly half your state is being discarded intermittently, with more state being discarded over time
> 
> From a time based perspective, one seed being nan is common enough that it will occur multiple times if you run math.random() for ~100ms
> 
> If both seeds are nan due to this, the generator will revert to a predefined sequence that is generated. This is quite bad, as after ~10 seconds at the most the generator will revert to a predefined state and produced a fixed sequence of numbers
> 
> To provide an example, the seed sequence s0 = 3873826803242720369, s1 = 3475268073314572095 should transform to s0 = 3475268073314572095, s1 = 9221203049127997123, but due to this s1 is 9221120237041090560 (NAN)
>
> ---
>
> Additionally this means that xorshift128+ as implemented only has a period of 682927953 (once this bug is hit), as found by counting until that number repeats again

Which means that you can abuse this bug in order to massively reduce the possible state space!

Of course, this requires that the bug is hit *on the server*, and the RNG state enters the fixed sequence.

How convenient, then, that the source includes this line at the start:

```js
for (let i = 0; i < 13371337; i++)
    Math.random();
```

The bug can trigger every 62 rolls (as that's how big a batch the implementation generates numbers in), and there's a 1/2048 chance the state will encode to a NaN double (the 11 exponent bits all need to be 1s). So on average, it'd take `1/(2048^2 * 62)` (or about 260 million) rolls for the bug to trigger for both state values at once, forcing the RNG into a fixed cycle. Since we step the RNG 13,371,337 rolls on startup, there's about a 5% chance that the seed phrase will be generated from somewhere within the cycle.

The period in terms of Math.random() calls is 682,927,953 (according to the bug tracker), but we have a slight advantage here: since we always step the same amount of rolls on startup, the seed phrase is always generated from the same "offset" within the current 62-roll block. Since the bug triggers on block *boundaries*, we can only be in one of 682,927,953/62 = 11,014,967 (...off by one) possible blocks, and at a known offset within them. So there can only ever be that many possible seed phrases!

## The solution
We can iterate all the 11,014,967 possible seeds and build a "rainbow table" of their respective 5-character "hints". It turns out there's only about 3 million *unique* hints. It's not going to be possible to identify which actual seed phrase corresponds to any given hint when there's duplicates, but that's okay.

Using this table (which is generated by `gen_table.js` - run it with `./gen_table.sh` to use the correct Node version), we can repeatedly connect to the remote, receive the hint, look up the seed phrase in the table, and hope we get lucky enough to both trigger the NaN bug and pick the right seed phrase for the hint.

In practice, this only takes 50-100 attempts, and gets you a flag within about a minute :)