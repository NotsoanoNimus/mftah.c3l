/**
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
module prng_test;

import mftah::prng;
import std::io;


const BREAK_AFTER = 8;

fn void main()
{
    Xoshiro256pp prng @noinit;
    prng.init();

    io::printn("Numbers of any size...");
    ulong[64] randoms;
    for (usz i = 0; i < 64; ++i) randoms[i] = prng.next();
    for (usz i = 0; i < 64; ++i) io::printf("%x,%c", randoms[i], (i+1) % BREAK_AFTER ? ' ' : '\n'); io::printn("\n");

    io::printf("Numbers between 100 (%x) and 1,000 (%x)...\n", 100, 1000);
    ulong[64] randoms_bounded;
    for (usz i = 0; i < 64; ++i) randoms_bounded[i] = prng.next_bounded(100, 1000);
    for (usz i = 0; i < 64; ++i) io::printf("%x,%c", randoms_bounded[i], (i+1) % BREAK_AFTER ? ' ' : '\n'); io::printn("\n");

    io::printn("Between 0 and 1 only...");
    for (usz i = 0; i < 64; ++i) randoms_bounded[i] = prng.next_bounded(0, 1);
    for (usz i = 0; i < 64; ++i) io::printf("%x,%c", randoms_bounded[i], (i+1) % BREAK_AFTER ? ' ' : '\n'); io::printn("\n");

    TinyMT64 t @noinit;
    t.init(prng.next());

    io::printn("Numbers from TinyMT64, seeded by next Xoshiro256++ value...");
    for (usz i = 0; i < 64; ++i) io::printf("%x,%c", t.generate_ulong(), (i+1) % BREAK_AFTER ? ' ' : '\n'); io::printn("\n");
}
