/**
 * Copyright (c) 2025 Zack Puhl (@NotsoanoNimus) - https://github.com/NotsoanoNimus/chacha20_aead.c3l
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
 */

// ===========================================================================================================
/* THIS SOURCE CODE HAS BEEN SLIGHTLY MODIFIED FROM ITS ORIGINAL STATE FOR COMPATIBILITY WITH THIS PROJECT. */
// ===========================================================================================================
module mftah::hashing::poly1305;

import mftah::util;

import std::io;   // TODO: REMOVE!!


const TAG_SIZE = 16;
const HASH_BYTES = 16;
const BLOCK_SIZE = 16;
const KEY_SIZE = 32;


struct Poly1305 (HmacDigestProvider)
{
    ulong[3]        h;
    ulong[2]        r;
    uint[4]         nonce;
    char[TAG_SIZE]  temp;
    usz             num;
}

const IPAD @private = 0x36;
const OPAD @private = 0x5C;

<*
 @require output.len > 0 : "Output must be greater than zero"
 @require output.len < int.max / HASH_BYTES : "Output is too large"
*>
fn void pbkdf2(char[] pw, char[] salt, uint iterations, char[] output)
{
	usz l = output.len / HASH_BYTES;
	usz r = output.len % HASH_BYTES;

	Poly1305 hmac;
	hmac.init(pw);

	char[] dst_curr = output;
	for (usz i = 1; i <= l; i++)
	{
		@derive(&hmac, salt, iterations, i, dst_curr[:HASH_BYTES]);
		dst_curr = dst_curr[HASH_BYTES..];
	}

	if (r > 0)
	{
		char[HASH_BYTES] tmp;
		@derive(&hmac, salt, iterations, l + 1, &tmp);
		dst_curr[..] = tmp[:dst_curr.len];
		mem::zero_volatile(&tmp);
	}
}

macro @derive(Poly1305 *hmac_start, char[] salt, uint iterations, usz index, char[] out)
{
	assert(out.len == HASH_BYTES);

	char[HASH_BYTES] tmp @noinit;
	defer mem::zero_volatile(&tmp);

	Poly1305 hmac  = *hmac_start;
	hmac.update(salt);

	UIntBE be = { (uint)index };
	hmac.update(&&bitcast(be, char[4]));

	tmp = hmac.finalize();
	out[..] = tmp[..];

	for (int it = 1; it < iterations; it++)
	{
		hmac = *hmac_start;
		hmac.update(&tmp);
		tmp = hmac.finalize();
		foreach (i, v : tmp) out[i] ^= v;
	}
}


fn char[] Poly1305.iface_digest(&self, char[] key, char[] data) @dynamic
{
	char[] res = malloc(TAG_SIZE)[:TAG_SIZE];
	res[:TAG_SIZE] = hash(key, data)[:TAG_SIZE];
	return res;
}

fn char[] Poly1305.iface_kdf(&self, char[] key, char[] salt, uint iterations) @dynamic
{
	char[] res = malloc(HASH_BYTES)[:HASH_BYTES];
	pbkdf2(key, salt, iterations, res);
	return res;
}

fn void Poly1305.iface_init(&self, char[] key) @dynamic => self.init(key);
fn void Poly1305.iface_update(&self, char[] data) @dynamic => self.update(data);

fn char[] Poly1305.iface_final(&self) @dynamic
{
	char[] res = malloc(TAG_SIZE)[:TAG_SIZE];
	res[:TAG_SIZE] = self.finalize()[:TAG_SIZE];
	return res;
}

fn usz Poly1305.iface_hashlen(&self) @dynamic => TAG_SIZE;


macro ulong u8_to_u64(char* in) @local
{
    ulong v = 0;

    $for var $i = 0; $i < 8; ++$i :
        v |= ((ulong)(in[$i] & 0xFF) << ($i * 8));
    $endfor

    return v;
}

macro uint u8_to_u32(char *in) @local
{
    uint v = 0;

    $for var $i = 0; $i < 4; ++$i :
        v |= ((uint)(in[$i] & 0xFF) << ($i * 8));
    $endfor

    return v;
}

macro void u64_to_8(char* out, ulong in) @local
{
    $for var $i = 0; $i < 8; ++$i :
        out[$i] = (char)((in >> ($i * 8)) & 0xFF);
    $endfor
}

macro ulong constant_time_carry(ulong a, ulong b) @local => ((a ^ ((a ^ b) | ((a - b) ^ b))) >> (ulong.sizeof * 8 - 1));


<*
    @require key.len == KEY_SIZE : "Key size must be exactly 32 bytes."
*>
fn char[TAG_SIZE] hash(char[] input, char[] key)
{
    Poly1305 p;   // do init this item, we want explicit 0 values

    p.init(key);
    p.update(input);

    return p.finalize();
}

fn char[TAG_SIZE] mac(char[] input, char[] key) => hash(input, key);
fn char[TAG_SIZE] tag(char[] input, char[] key) => hash(input, key);


fn void Poly1305.init(&self, char[] key)
    => *self = {
        .r = { u8_to_u64(&key[0]) & 0x0FFF_FFFC_0FFF_FFFF, u8_to_u64(&key[8]) & 0x0FFF_FFFC_0FFF_FFFC },
        .nonce = { u8_to_u32(&key[16]), u8_to_u32(&key[20]), u8_to_u32(&key[24]), u8_to_u32(&key[28]) },
    };


fn void Poly1305.update(&self, char[] input)
{
    usz rem;
    usz num = self.num;

    usz len = input.len;
    char* scroll = input.ptr;

    if (num) {
        rem = BLOCK_SIZE - num;

        if (len >= rem) {
            for (int i = 0; i < rem; ++i) self.temp[num + i] = scroll[i];   // memcpy(self.temp + num, scroll, rem);

            self.blocks(self.temp[:BLOCK_SIZE]);

            scroll += rem;
            len -= rem;
        } else {
            for (int i = 0; i < len; ++i) self.temp[num + i] = scroll[i];   // memcpy(self.temp + num, scroll, len);

            self.num = num + len;
            return;
        }
    }

    rem = len % BLOCK_SIZE;
    len -= rem;

    if (len >= BLOCK_SIZE) {
        self.blocks(scroll[:len]);

        scroll += len;
    }

    if (rem) {
        for (int i = 0; i < rem; ++i) self.temp[i] = scroll[i];   // memcpy(self.temp, scroll, rem);
    }

    self.num = rem;
}


fn char[TAG_SIZE] Poly1305.finalize(&self)
{
    char[TAG_SIZE] result;

    usz num = self.num;

    // Clean up leftover data (when not an even BLOCK_SIZE).
    if (num) {
        self.temp[num++] = 1;

        while (num < BLOCK_SIZE) self.temp[num++] = 0;

        self.blocks(self.temp[:BLOCK_SIZE], 0);
    }

    // Emit.
    ulong h0 = self.h[0];
    ulong h1 = self.h[1];
    ulong h2 = self.h[2];

    uint128 t;

    t = (uint128)h0 + 5;
    ulong g0 = (ulong)t;

    t = (uint128)h1 + (t >> 64);
    ulong g1 = (ulong)t;

    ulong g2 = h2 + (ulong)(t >> 64);

    ulong mask = 0 - (g2 >> 2);
    g0 &= mask;
    g1 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;

    t = (uint128)h0 + self.nonce[0] + ((uint128)self.nonce[1] << 32);
    h0 = (ulong)t;

    t = (uint128)h1 + self.nonce[2] + ((uint128)self.nonce[3] << 32) + (t >> 64);
    h1 = (ulong)t;

    // Store.
    u64_to_8(&result[0 * ulong.sizeof], h0);
    u64_to_8(&result[1 * ulong.sizeof], h1);

    // Clear context values.
    self.h = { 0, 0, 0 };
    self.r = { 0, 0 };
    self.nonce = { 0, 0, 0, 0 };
    self.temp = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    self.num = 0;

    return result;
}


fn void Poly1305.blocks(&self, char[] input, ulong pad_bit = 1) @local
{
    ulong r0 = self.r[0];
    ulong r1 = self.r[1];

    ulong s1 = r1 + (r1 >> 2);

    ulong h0 = self.h[0];
    ulong h1 = self.h[1];
    ulong h2 = self.h[2];

    ulong c = 0;
    uint128 d0 = 0;
    uint128 d1 = 0;

    usz len = input.len;
    char* scroll = input.ptr;

    while (len >= BLOCK_SIZE) {
        d0 = (uint128)h0 + u8_to_u64(scroll + 0);
        h0 = (ulong)d0;

        d1 = (uint128)h1 + (d0 >> 64) + u8_to_u64(scroll + 8);
        h1 = (ulong)d1;

        h2 += (ulong)(d1 >> 64) + pad_bit;

        d0 = ((uint128)h0 * r0) + ((uint128)h1 * s1);
        d1 = ((uint128)h0 * r1) + ((uint128)h1 * r0) + ((uint128)h2 * s1);
        h2 = (h2 * r0);

        h0 = (ulong)d0;

        d1 = d1 + (d0 >> 64);
        h1 = (ulong)d1;
        h2 = h2 + (ulong)(d1 >> 64);

        c = (h2 >> 2) + (h2 & ~(ulong)3);

        h2 &= 3;
        h0 += c;
        c = constant_time_carry(h0, c);
        h1 += c;
        h2 += constant_time_carry(h1, c);

        scroll += BLOCK_SIZE;
        len -= BLOCK_SIZE;
    }

    self.h[0] = h0;
    self.h[1] = h1;
    self.h[2] = h2;
}



// -----------------------------------------------------------------------------------
// TESTS
fn void poly1305__rfc8439_s2_5_2() @test
{
    char[] key = { 0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b };
    char[] plaintext = "Cryptographic Forum Research Group";

    char[poly1305::TAG_SIZE] tag = poly1305::hash(plaintext[..^1], key);   // len - 1 to get rid of the null-terminator

    char[] expected_tag = { 0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9 };

    assert(tag[:poly1305::TAG_SIZE] == expected_tag, "`poly1305::hash()`: Did not get expected tag.");
}
