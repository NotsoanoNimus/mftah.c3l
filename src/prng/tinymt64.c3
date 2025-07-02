/**
 * @file tinymt64.c3
 *
 * @brief 64-bit Tiny Mersenne Twister only 127 bit internal state
 *
 * @author Mutsuo Saito (Hiroshima University)
 * @author Makoto Matsumoto (The University of Tokyo)
 *
 * @author Zack Puhl <github@xmit.xyz> - Converted to C3.
 *
 *  Copyright (c) 2011, 2013 Mutsuo Saito, Makoto Matsumoto,
 *  Hiroshima University and The University of Tokyo.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials provided
 *        with the distribution.
 *      * Neither the name of the Hiroshima University nor the names of
 *        its contributors may be used to endorse or promote products
 *        derived from this software without specific prior written
 *        permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ========================================================================
 * C3 code variant is available under the MIT License.
 *
 * Copyright (c) 2025 Zack Puhl <github@xmit.xyz>
 *
 */
module mftah::prng::tinymt64;


const TINYMT64_MEXP  = 127;
const TINYMT64_SH0   = 12;
const TINYMT64_SH1   = 11;
const TINYMT64_SH8   = 8;
const TINYMT64_MASK  = 0x7fffffffffffffff;
const TINYMT64_MUL   = (1.0 / 9007199254740992.0);

const MIN_LOOP = 8;


/*
 * tinymt64 internal state vector and parameters
 */
struct TinyMT64
{
    ulong[2]    status;
    uint        mat1;
    uint        mat2;
    ulong       tmat;
}

// Used in a few local functions to quickly convert between ulong and double while operating on the same value.
union InternalConv @local
{
    ulong u;
    double d;
}


<*
 * This function changes internal state of tinymt64.
 *   Users should not call this function directly.
 *>
fn void TinyMT64.next_state(&self) @local
{
    ulong x;

    self.status[0] &= TINYMT64_MASK;

    x = self.status[0] ^ self.status[1];
    x ^= x << TINYMT64_SH0;
    x ^= x >> 32;
    x ^= x << 32;
    x ^= x << TINYMT64_SH1;

    self.status[0] = self.status[1];
    self.status[1] = x;

    if ((x & 1) != 0)
    {
        self.status[0] ^= self.mat1;
        self.status[1] ^= ((ulong)self.mat2 << 32);
    }
}


<*
 * This function outputs 64-bit unsigned integer from internal state.
 *   Users should not call this function directly.
 *
 * @return "A 64-bit, unsigned, pseudorandom number"
 *>
fn ulong TinyMT64.temper(&self) @local
{
    ulong x;

    $if $defined(LINEARITY_CHECK) :
        x = self.status[0] ^ self.status[1];
    $else
        x = self.status[0] + self.status[1];
    $endif

    x ^= (self.status[0] >> TINYMT64_SH8);

    if ((x & 1) != 0)
    {
        x ^= self.tmat;
    }

    return x;
}


<*
 * This function outputs floating point number from internal state.
 *   Users should not call this function directly.
 *
 * @return "floating point number r (1.0 <= r < 2.0)"
 *>
fn double TinyMT64.temper_conv(&self) @local
{
    ulong x;
    InternalConv conv;

    $if $defined(LINEARITY_CHECK) :
        x = self.status[0] ^ self.status[1];
    $else
        x = self.status[0] + self.status[1];
    $endif

    x ^= self.status[0] >> TINYMT64_SH8;

    if ((x & 1) != 0)
    {
        conv.u = ((x ^ self.tmat) >> 12) | 0x3ff0000000000000;
    }
    else
    {
        conv.u = (x  >> 12) | 0x3ff0000000000000;
    }

    return conv.d;
}


<*
 * This function outputs floating point number from internal state.
 *   Users should not call this function directly.
 *
 * @return "floating point number r (1.0 < r < 2.0)"
 *>
fn double TinyMT64.temper_conv_open(&self) @local
{
    ulong x;
    InternalConv conv;

    $if $defined(LINEARITY_CHECK) :
        x = self.status[0] ^ self.status[1];
    $else
        x = self.status[0] + self.status[1];
    $endif

    x ^= self.status[0] >> TINYMT64_SH8;

    if ((x & 1) != 0)
    {
        conv.u = ((x ^ self.tmat) >> 12) | 0x3ff0000000000001;
    }
    else
    {
        conv.u = (x >> 12) | 0x3ff0000000000001;
    }

    return conv.d;
}


<*
 * This function outputs 64-bit unsigned integer from internal state.
 *
 * @return "64-bit unsigned integer r (0 <= r < 2^64)"
 *>
fn ulong TinyMT64.generate_ulong(&self)
{
    self.next_state();

    return self.temper();
}


<*
 * Added for C3 bounded arrays. Populate a provided slice of ulong values.
 *
 * @param [&in] input : "The slice to populate."
 * @require input.len > 0 : "It is useless to call this method without at least one slice item returned."
 *>
fn void TinyMT64.populate_ulong_slice(&self, ulong[] input)
{
    for (usz i = 0; i < input.len; ++i) input[i] = self.generate_ulong();
}


<*
 * This function outputs floating point number from internal state.
 *   This function is implemented using multiplying by (1 / 2^53).
 *
 * @return "floating point number r (0.0 <= r < 1.0)"
 *>
fn double TinyMT64.generate_double(&self)
{
    self.next_state();

    return (double)(self.temper() >> 11) * TINYMT64_MUL;
}


<*
 * Added for C3 bounded arrays. Populate a provided slice of double values.
 *
 * @param [&in] input : "The slice to populate."
 * @require input.len > 0 : "It is useless to call this method without at least one slice item returned."
 *>
fn void TinyMT64.populate_double_slice(&self, double[] input)
{
    for (usz i = 0; i < input.len; ++i) input[i] = self.generate_double();
}


<*
 * This function outputs floating point number from internal state.
 *   This function is implemented using union trick.
 *
 * @return "floating point number r (0.0 <= r < 1.0)"
 *>
fn double TinyMT64.generate_double01(&self)
{
    self.next_state();

    return self.temper_conv() - 1.0;
}


<*
 * This function outputs floating point number from internal state.
 *   This function is implemented using union trick.
 *
 * @return "floating point number r (1.0 <= r < 2.0)"
 *>
fn double TinyMT64.generate_double12(&self)
{
    self.next_state();

    return self.temper_conv();
}


<*
 * This function outputs floating point number from internal state.
 *   This function is implemented using union trick.
 *
 * @return "floating point number r (0.0 < r <= 1.0)"
 *>
fn double TinyMT64.generate_doubleOC(&self)
{
    self.next_state();

    return 2.0 - self.temper_conv();
}


<*
 * This function outputs floating point number from internal state.
 *   This function is implemented using union trick.
 *
 * @return "floating point number r (0.0 < r < 1.0)"
 *>
fn double TinyMT64.generate_doubleOO(&self)
{
    self.next_state();

    return self.temper_conv_open() - 1.0;
}


<*
 * This function represents a function used in the initialization by init_by_array.
 *
 * @param [in] x : "64-bit integer"
 * @return "64-bit integer"
 *>
fn ulong ini_func1(ulong x) @local => (x ^ (x >> 59)) * 2173292883993;


<*
 * This function represents a function used in the initialization by init_by_array.
 *
 * @param [in] x : "64-bit integer"
 * @return "64-bit integer"
 *>
fn ulong ini_func2(ulong x) @local => (x ^ (x >> 59)) * 58885565329898161;


<*
 * This function certificate the period of 2^127-1.
 *>
fn void TinyMT64.period_certification(&self) @local
{
    if ((self.status[0] & TINYMT64_MASK) == 0 && self.status[1] == 0)
    {
        self.status[0] = 'T';
        self.status[1] = 'M';
    }
}


<*
 * This function initializes the internal state array with a 64-bit * unsigned integer seed.
 *
 * @param [in] seed : "64-bit unsigned integer used as a seed."
 *>
fn void TinyMT64.init(&self, ulong seed)
{
    // TODO: This should be generated with the tinym64dc application/functions dynamically!
    self.mat1 = 0x65980cb3;
    self.mat2 = 0xeb38facf;
    self.tmat = 0xcc3b75ff;

    self.status[0] = seed ^ ((ulong)self.mat1 << 32);
    self.status[1] = self.mat2 ^ self.tmat;

    for (uint i = 1; i < MIN_LOOP; i++)
    {
        self.status[i & 1] ^= i + 6364136223846793005
            * (self.status[(i - 1) & 1]
               ^ (self.status[(i - 1) & 1] >> 62));
    }

    self.period_certification();
}


<*
 * This function initializes the internal state array, with an array of 64-bit unsigned integers used as seeds.
 *
 * @param [in] init_key : "slice of 64-bit integers, used as a seed."
 *>
fn void TinyMT64.init_by_array(&self, ulong[] init_key)
{
    uint lag = 1;
    uint mid = 1;
    uint size = 4;

    uint i, j;
    uint count;

    ulong r;

    ulong[4] st;

    // TODO: This should be generated with the tinym64dc application/functions dynamically!
    self.mat1 = 0x65980cb3;
    self.mat2 = 0xeb38facf;
    self.tmat = 0xcc3b75ff;

    st[0] = 0;
    st[1] = self.mat1;
    st[2] = self.mat2;
    st[3] = self.tmat;

    if (init_key.len + 1 > MIN_LOOP)
    {
        count = (uint)init_key.len + 1;
    }
    else
    {
        count = MIN_LOOP;
    }

    r = ini_func1(st[0] ^ st[mid % size] ^ st[(size - 1) % size]);

    st[mid % size] += r;

    r += (uint)init_key.len;

    st[(mid + lag) % size] += r;
    st[0] = r;

    count--;

    for (i = 1, j = 0; (j < count) && (j < (uint)init_key.len); j++)
    {
        r = ini_func1(st[i] ^ st[(i + mid) % size] ^ st[(i + size - 1) % size]);
        st[(i + mid) % size] += r;
        r += init_key[j] + i;
        st[(i + mid + lag) % size] += r;
        st[i] = r;
        i = (i + 1) % size;
    }

    for (; j < count; j++)
    {
        r = ini_func1(st[i] ^ st[(i + mid) % size] ^ st[(i + size - 1) % size]);
        st[(i + mid) % size] += r;
        r += i;
        st[(i + mid + lag) % size] += r;
        st[i] = r;
        i = (i + 1) % size;
    }

    for (j = 0; j < size; j++)
    {
        r = ini_func2(st[i] + st[(i + mid) % size] + st[(i + size - 1) % size]);
        st[(i + mid) % size] ^= r;
        r -= i;
        st[(i + mid + lag) % size] ^= r;
        st[i] = r;
        i = (i + 1) % size;
    }

    self.status[0] = st[0] ^ st[1];
    self.status[1] = st[2] ^ st[3];

    self.period_certification();
}
