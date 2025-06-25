/**
 * @file xoshiro.c3
 * @brief PRNG implementations for MFTAH, using tinymt64 and Xoshiro128+.
 *
 * @author Zack Puhl <github@xmit.xyz>
 * @date 2025-06-25
 * 
 * 
 * Copyright (c) 2025 Zack Puhl <github@xmit.xyz> - https://github.com/NotsoanoNimus/mftah.c3l
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
module mftah::prng::xoshiro;

import mftah::prng::tinymt64;


struct Xoshiro128p
{
    ulong[2]    state;
    bool        is_locked;
}


fn ulong rotl(ulong x, int k) @local => ((x << k) | (x >> (64 - k)));


<*
 * Initialize the Xoshiro128+ PRNG with a seed from a TinyMT64 run, seeded itself from RDTSC.
 *>
fn void Xoshiro128p.init(&self)
{
    self.is_locked = true;

    // Get the amount of cycles since the processor was powered on.
    //   This should act as a sufficient non-time-based PRNG seed.
    //
    // TODO: Should this rdtsc value only be initialized ONCE at program start?
    uint lo, hi;
    asm
    {
        rdtsc;
        movl lo, $eax;
        movl hi, $edx;
    }

    ulong seed_value = (((ulong)hi << 32) | lo);

    TinyMT64 initializer_prng @noinit;
    initializer_prng.init(seed_value);
    initializer_prng.populate_ulong_slice(&self.state);

    self.is_locked = false;
}


fn ulong Xoshiro128p.next_bounded(&self, ulong low, ulong high)
{
    while (self.is_locked);

    self.is_locked = true;

    ulong range = 1 + high - low;

    ulong s0 = self.state[0];
    ulong s1 = self.state[1];
    ulong result = s0 + s1;

    s1 ^= s0;

    self.state[0] = rotl(s0, 24) ^ s1 ^ (s1 << 16);
    self.state[1] = rotl(s1, 37);

    self.is_locked = false;

    return (
        (ulong)(high > low)
        * (
            (
                result
                % (
                    (
                        ((ulong)(0 == range) * 1)
                        + range
                    )
                )
            )
            + low
        )
    );
}


fn ulong Xoshiro128p.next(&self) => self.next_bounded(0, ulong.max ^ (ulong)1);
