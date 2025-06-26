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
module mftah_stream_test;

import mftah;

import std::io;
import libc;


fn void free(void* ptr) => libc::free(ptr);

const BLOCK_SIZE = (1 << 4) * (1024 * 1024);

usz ctr = 0;
char[] data = $embed("misc/test_input.data");

fn char[] next_block()
{
    if (ctr >= data.len) return {};

    char[] block = (data.len - ctr) < BLOCK_SIZE
        ? data[ctr : BLOCK_SIZE]
        : data[ctr : (data.len - ctr)];

    ctr += BLOCK_SIZE;

    return block;
}

fn void yield(char[] data) => util::@slicedump(libc::printf, data[:util::@min(64, data.len)]);


const ZString IMMUTABLE_STRING = "I am secured data!";

fn void main()
{
    char[] sequence = (libc::strdup(IMMUTABLE_STRING))[:libc::strlen(IMMUTABLE_STRING)];
    char[] key = "APPLE_SAUCE";

    HooksTable hooks = {
        .malloc = &libc::malloc,
        .calloc = &libc::calloc,
        .realloc = &libc::realloc,
        .memcpy = &libc::memcpy,
        .memset = &libc::memset,
        .memmove = &libc::memmove,
        .memcmp = &libc::memcmp,
        .free   = &free,
    };

    mftah::stream_new({ hooks, key, 1, &next_block, &yield }, CryptoType.AES_256_CBC_HMAC_SHA256)!!;
}
