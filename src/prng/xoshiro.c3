/**
 * @file xoshiro.c3
 * @brief PRNG implementations for MFTAH, using tinymt64 and Xoshiro256++.
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


struct Xoshiro256pp
{
    ulong[4]    state;
    bool        is_locked;
}


fn ulong rotl(ulong x, int k) @local => ((x << k) | (x >> (64 - k)));


<*
 * Initialize the Xoshiro256++ PRNG with a seed from a TinyMT64 run, seeded itself from RDTSC.
 *>
fn void Xoshiro256pp.init(&self)
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



<*
 * @require high > low : "The upper bound must be greater than the lower bound."
 * @require high <= (ulong.max - (ulong)2) : "The upper bound should not exceed (uint64_max - 2)."
 *>
fn ulong Xoshiro256pp.next_bounded(&self, ulong low, ulong high)
{
    while (self.is_locked);

    self.is_locked = true;

    ulong result = rotl(self.state[0] + self.state[3], 23) + self.state[0];

	ulong t = self.state[1] << 17;

	self.state[2] ^= self.state[0];
	self.state[3] ^= self.state[1];
	self.state[1] ^= self.state[2];
	self.state[0] ^= self.state[3];

	self.state[2] ^= t;

	self.state[3] = rotl(self.state[3], 45);

    self.is_locked = false;

	return (result % (high - low)) + low;
}


fn ulong Xoshiro256pp.next(&self) => self.next_bounded(0, ulong.max - (ulong)2);


const ulong[4] JUMP = { 0x180ec6d33cfd0aba, 0xd5a61266f0c9392c, 0xa9582618e03fc9aa, 0x39abdc4529b1661c };

/**
 * This is the jump function for the generator. It is equivalent
 *  to 2^128 calls to next(); it can be used to generate 2^128
 *  non-overlapping subsequences for parallel computations.
 */
fn void Xoshiro256pp.jump(&self)
{
	ulong s0 = 0;
	ulong s1 = 0;
	ulong s2 = 0;
	ulong s3 = 0;

	for (int i = 0; i < JUMP.len; ++i)
    {
		for (int b = 0; b < 64; ++b)
        {
			if (JUMP[i] & (ulong)1 << b)
            {
				s0 ^= self.state[0];
				s1 ^= self.state[1];
				s2 ^= self.state[2];
				s3 ^= self.state[3];
			}

			(void)self.next();
		}
    }
		
	self.state[0] = s0;
	self.state[1] = s1;
	self.state[2] = s2;
	self.state[3] = s3;
}


const ulong[4] LONG_JUMP = { 0x76e15d3efefdcbbf, 0xc5004e441c522fb3, 0x77710069854ee241, 0x39109bb02acbe635 };

/**
 * This is the long-jump function for the generator. It is equivalent to
 *  2^192 calls to next(); it can be used to generate 2^64 starting points,
 *  from each of which jump() will generate 2^64 non-overlapping
 *  subsequences for parallel distributed computations.
 */
fn void Xoshiro256pp.long_jump(&self)
{
	ulong s0 = 0;
	ulong s1 = 0;
	ulong s2 = 0;
	ulong s3 = 0;

	for (int i = 0; i < 4; ++i)
    {
		for (int b = 0; b < 64; ++b)
        {
			if (LONG_JUMP[i] & (ulong)1 << b)
            {
				s0 ^= self.state[0];
				s1 ^= self.state[1];
				s2 ^= self.state[2];
				s3 ^= self.state[3];
			}

			(void)self.next();	
		}
    }
		
	self.state[0] = s0;
	self.state[1] = s1;
	self.state[2] = s2;
	self.state[3] = s3;
}
