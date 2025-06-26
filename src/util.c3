/**
 * @file util.c3
 * @brief MFTAH utilities which would otherwise crowd the primary 'mftah' source file.
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
module mftah::util;


macro @min(#x, #y) => #x < #y ? #x : #y;
macro @max(#x, #y) => #x > #y ? #x : #y;

macro @memdump(#printf, #ptr, #len, $width = 16)
{
    for (usz i = 0; i < #len; ++i) {
        (#printf)("%02x%c", ((char*)#ptr)[i], (i+1) % $width ? ' ' : '\n');
    }
    (#printf)("\n");
}

macro @slicedump(#printf, #slice, $width = 16)
    => @memdump(#printf, (#slice).ptr, #slice.len * $typeof(#slice[0]).sizeof, $width);

macro @w($str) @const
{
    $if $defined(MFTAH_WIDESTR) :
        return $$wstr16($str);
    $else
        return $str;
    $endif
}


import mftah::hashing;
import mftah::crypto;

macro void? @set_payload_services(CryptoType crypto_type, #malloc, #hash, #hmac, #crypto)
{
    DigestProvider* d;
    HmacDigestProvider* h;
    CryptoProvider* c;

    switch (crypto_type) {
        case AES_256_CBC_HMAC_SHA256:
            d = #malloc(Sha256.sizeof);
            h = #malloc(HmacSha256.sizeof);
            c = #malloc(AesCtx.sizeof);

        case AEAD_CHACHA20_POLY1305:
            d = #malloc(Sha256.sizeof);
            h = #malloc(HmacSha256.sizeof);
            c = #malloc(AesCtx.sizeof);

        default:
            return mftah::INVALID_CRYPTO_TYPE?;
    }

    #hash   = d;
    #hmac   = h;
    #crypto = c;
}
