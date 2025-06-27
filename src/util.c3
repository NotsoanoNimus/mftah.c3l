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

macro @slicedump(#printf, slice, $width = 16)
    => @memdump(#printf, slice.ptr, slice.len * $typeof(slice[0]).sizeof, $width);

macro @w($str) @const
{
    $if $defined(MFTAH_WIDESTR) :
        return $$wstr16($str);
    $else
        return $str;
    $endif
}


<*
 * PKCS#7 padding scheme for block ciphers which do not have their own padding standards (e.g., AES-CBC).
 *   It's so easy that it's actually sus how quickly expected results were churned out...
 *
 * @param #realloc : "An expression which provides the LIBC realloc function, or an equivalent."
 * @param block_size : "The block size of the cipher suite whose ingested plaintext data will be padded."
 * @param input : "The input data to reallocate and pad."
 * @return "A slice representing the reallocated and PKCS#7-padded plaintext."
 *
 * @require block_size > 0 : "The cipher's block size CANNOT equal 0."
 * @ensure return.len >= block_size : "The returned slice's length MUST be >= the cipher's block size."
 *>
macro char[]? @pkcs7(#realloc, usz block_size, char[] input)
{
    usz pad_len = block_size - (input.len % block_size);   // note: even-sized inputs get an extra block

    char* new_ptr = #realloc(input.ptr, input.len + pad_len);
    if (null == new_ptr) return mftah::OUT_OF_RESOURCES?;

    for (usz i = input.len; i < (input.len + pad_len); ++i) new_ptr[i] = (char)(pad_len & 0xFF);

    return new_ptr[:(input.len + pad_len)];
}


<*
 * Strip the PKCS#7 padding off the end of the provided plaintext. All this really does is
 *   return a slice which has a shorter length by whatever the detected padding is.
 *
 * @param block_size : "The block size of the used cipher suite."
 * @param input : "The input plaintext which should be un-padded."
 * @return "A slice of the input plaintext with the trailing padding removed via the 'len' member."
 *>
macro char[]? @unpkcs7(usz block_size, char[] input)
{
    if (input.len < block_size) return mftah::PAYLOAD_NOT_PADDED?;

    // The padding length in PKCS#7 can always be derived from the final byte of the padded plaintext.
    char pad_len = input[^1];

    // Of course, the padding length should never exceed the input length or the block size.
    if (input.len < pad_len || pad_len > block_size) return mftah::INVALID_PAYLOAD_PADDING?;

    // If padding IS the entire input, return an empty slice.
    //   Else, return the input with the padding trimmed.
    return input.len == pad_len ? input[:0] : input[..^(pad_len + 1)];
}


import mftah::hashing;
import mftah::crypto;

<*
 * Assign implementors to each given interface pointer expression, based on the selected crypto type/suite.
 *>
macro void? @set_payload_services(
    CryptoType crypto_type, #malloc, #hash, #o_hmac, #w_hmac, #crypto)
{
    switch (crypto_type) {
        case AES_256_CBC_HMAC_SHA256:
            Sha256* h = #malloc(Sha256.sizeof);             #hash = h;
            HmacSha256* ho = #malloc(HmacSha256.sizeof);    #o_hmac = ho;
            HmacSha256* hw = #malloc(HmacSha256.sizeof);    #w_hmac = hw;
            AesCtx* c = #malloc(AesCtx.sizeof);             #crypto = c;

        default: return mftah::INVALID_CRYPTO_TYPE?;
    }
}
