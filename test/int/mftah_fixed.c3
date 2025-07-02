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
module mftah_fixed_test;

import mftah;

import std::io;
import libc;


usz ctr = 0;
// char[] data_const = "test"[:4];
char[] data_const = $embed("misc/test_input.data");
char[] data = {};

File out_file;


fn void main()
{
    char[] key = "applesauce";

    io::printn("Setting up...");
    data = calloc(data_const.len)[:data_const.len];
    assert(null != data.ptr);
    data[..] = data_const[..];

    out_file = file::open("/tmp/encrypted_fixed.mftah", "w")!!;
    out_file.seek(0)!!;
    defer (void)out_file.close();

    io::printn("Encrypting input...");
    char[] result = mftah::new(data, key, CHACHA20_POLY1305, 8, 459)!!;

    io::printn("Writing out-file...");
    out_file.write(result)!!;
}
