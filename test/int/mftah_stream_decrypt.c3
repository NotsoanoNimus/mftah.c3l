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
module mftah_stream_decrypt_test;

import mftah;

import std::io;
import std::io::file;
import libc;


fn void free(void* ptr) => (void)libc::free(ptr);

usz ctr = 0;
char[] data_const = $embed("../../../../../../../../../../tmp/encrypted_stream.mftah");
char[] data = {};

File out_file;


fn char[] next_block(usz block_size)
{
    if (block_size != data.len) {
        if (null != data.ptr) free(data);
        data = calloc(block_size)[:block_size];
    }

    if (ctr >= data_const.len) return {};

    usz span = (data_const.len - ctr) < block_size ? (data_const.len - ctr) : block_size;

    io::printf("READ_BLOCK at (%d [:%d] / %d)...\n", ctr, span, data_const.len);
    data[:span] = data_const[ctr:span];

    ctr += span;

    return data[:span];
}

fn void yield(char[] data)
{
    util::@slicedump(libc::printf, data[:util::@min(256, data.len)], 32);
    out_file.write(data)!!;
}


fn void main()
{
    char[] key = "applesauce";

    out_file = file::open("/tmp/decrypted_stream.mftah", "w")!!;
    out_file.seek(0)!!;
    defer out_file.close()!!;

    mftah::stream_decrypt(key, &next_block, &yield)!!;
}
