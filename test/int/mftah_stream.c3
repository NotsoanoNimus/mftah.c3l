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


fn void free(void* ptr) => (void)libc::free(ptr);

const BLOCK_SIZE = (1 << 4) * (1024 * 1024);

usz ctr = 0;
char[] data_const = "test"[:4];
// char[] data_const = $embed("misc/test_input.data");
char[] data = {};

fn char[] next_block()
{
    if (ctr >= data_const.len) return malloc(1)[:0];

    usz span = (data_const.len - ctr) < BLOCK_SIZE ? (data_const.len - ctr) : BLOCK_SIZE;

    io::printf("READ_BLOCK at (%d [:%d] / %d)...\n", ctr, span, data_const.len);
    data[:span] = data_const[ctr:span];

    ctr += span;

    return data[:span];
}

fn void yield(char[] data) => util::@slicedump(libc::printf, data[:util::@min(256, data.len)], 32);


const ZString IMMUTABLE_STRING = "!";

fn void main()
{
    char[] key = "applesauce";
    data = calloc(BLOCK_SIZE)[:BLOCK_SIZE];
    // usz testlen = BLOCK_SIZE*16 + (1024*1024); data_const = calloc(testlen)[:testlen];

    char[] test = sha256::hmac(sha256::hash(key)[..], data_const)[..];
    util::@slicedump(io::printf, test);

    // char[] sequence = util::@pkcs7(
    //     aes::BLOCKLEN,
    //     libc::strdup(IMMUTABLE_STRING)[:libc::strlen(IMMUTABLE_STRING)]
    // )!!;
    // char[] key = x"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"[..];
    // char[] iv = x"10101010101010101010101010101010"[..];

    // AesCtx* c = calloc(AesCtx.sizeof);
    // CryptoProvider p = c;

    // p.iface_init(key, iv)!!;

    // p.encrypt_mut(sequence)!!;
    // util::@slicedump(io::printf, sequence);

    // p.update_iv(iv)!!;
    // p.decrypt_mut(sequence)!!;
    // util::@slicedump(io::printf, util::@unpkcs7(p.block_size(), sequence)!!);

    // return;

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

    mftah::stream_new({ hooks, key, CryptoType.AES_256_CBC_HMAC_SHA256, 1, &next_block, &yield })!!;
 
    free(data);
}
