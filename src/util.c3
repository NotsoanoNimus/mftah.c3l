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

struct CryptoTypeToProviders @private
{
    CryptoType  type;
    typeid      digest;
    typeid      o_hmac;
    typeid      w_hmac;
    typeid      crypto;
}

const CryptoTypeToProviders[] TYPES_TO_PROVIDERS @local = {
    { AES_256_CBC_HMAC_SHA256, Sha512.typeid, HmacSha256.typeid, HmacSha256.typeid, AesCtx.typeid },
    // { AEAD_CHACHA20_POLY1305, Sha512.typeid, Poly1305.typeid, Poly1305.typeid, ChaCha20.typeid },
};


macro void? @set_payload_services(
    CryptoType crypto_type, #malloc, #hash, #o_hmac, #w_hmac, #crypto)
{
    DigestProvider* d;
    HmacDigestProvider* ho;
    HmacDigestProvider* hw;
    CryptoProvider* c;

    do OUTER: {
        foreach (mapping : TYPES_TO_PROVIDERS) {
            if (mapping.type != crypto_type) continue;

            d  = #malloc(mapping.digest.sizeof);
            ho = #malloc(mapping.o_hmac.sizeof);
            hw = #malloc(mapping.w_hmac.sizeof);
            c  = #malloc(mapping.crypto.sizeof);

            if (null == d || null == ho || null == hw || null == c) {
                return mftah::OUT_OF_RESOURCES?;
            }

            break OUTER;
        }

        return mftah::INVALID_CRYPTO_TYPE?;
    } while (true);

    #hash   = *d;
    #o_hmac = *ho;
    #w_hmac = *hw;
    #crypto = *c;
}
