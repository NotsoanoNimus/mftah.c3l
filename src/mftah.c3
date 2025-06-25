/**
 * @file mftah.c3
 * @brief MFTAH file format specification and interface.
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
module mftah;


enum MftahVersion : uint (char major, char minor, ushort release)
{
    INITIAL_RELEASE         = { 1, 0, 0 },
    DYNAMIC_CRYPTO          = { 2, 0, 512 }
}
const MftahVersion CURRENT = DYNAMIC_CRYPTO;

enum LogLevel : char (inline char raw)
{
    FATAL   = 1,
    ERROR   = 2,
    WARNING = 3,
    NOTICE  = 4,
    INFO    = 5,
    DEBUG   = 6,
    VERBOSE = 7,
}

enum PayloadState : char
{
    INVALID,
    ENCRYPTED,
    DECRYPTED,
    UNKNOWN,
}

enum WorkType : char
{
    ENCRYPT,
    DECRYPT,
}

enum CryptoType : ushort
{
    AES_256_CBC_HMAC_SHA256,
    AEAD_CHACHA20_POLY1305,
}


faultdef
    FAIL_GENERIC,
    NOT_YET_IMPLEMENTED,
    MISSING_PAYLOAD,
    INVALID_PARAMETER,
    INVALID_ALIGNMENT,
    OUT_OF_RESOURCES,
    INVALID_SIGNATURE,
    BAD_PAYLOAD_STATE,
    PAYLOAD_NOT_DECRYPTED,
    INVALID_PASSWORD,
    INVALID_THREAD_COUNT,
    INVALID_CRYPTO_TYPE,
    INVALID_STREAM_STATE,
    BAD_STREAM_BLOCK_SIZE,
    BAD_STREAM_PAYLOAD_LENGTH,
    BAD_W_HMAC,
    BAD_O_HMAC,
    BAD_PAYLOAD_LEN,
    BAD_IV,
    BAD_IV_SEEDS,
    BAD_PW_HASH,
    THREAD_BUSY,
    MISPLACED_PASSWORD_CHECK,
    STREAM_MISSING_POST_HEADER,
    PREMATURE_END_OF_STREAM,
    STREAM_LAST_BLOCK_TOO_LARGE
    ;

alias FnMftahPrintf = fn void (LogLevel, char[], ...);
alias FnMalloc = fn void* (usz);
alias FnCalloc = fn void* (usz, usz);
alias FnRealloc = fn void* (void*, usz);
alias FnMemcpy = fn void* (void*, void*, usz);
alias FnMemset = fn void* (void*, int, usz);
alias FnMemmove = fn void* (void*, void*, usz);
alias FnMemcmp = fn int (void*, void*, usz);
alias FnFree = fn void (void*);
alias FnProgressReporter = fn void (ulong current, ulong out_of, void* extra = null);
alias FnYield = fn void (char[] flushed_block);

struct HooksTable
{
    FnMftahPrintf       printf;
    FnMalloc            malloc;
    FnCalloc            calloc;
    FnRealloc           realloc;
    FnMemcpy            memcpy;
    FnMemset            memset;
    FnMemmove           memmove;
    FnMemcmp            memcmp;
    FnFree              free;
    FnYield             yield;
    FnProgressReporter  progress;
}

struct WorkOrder
{
    char[]      input;
    WorkType    work_type;
    CryptoType  crypto_type;
    uint        thread_index;
    bool        suppress_progress;
}

bitstruct StreamFlags : char
{
    bool                enabled     : 0;
    char                chunk_size  : 1..6;
    bool                canary      : 7;
}

struct PayloadHeader @packed
{
    char[8]             magic;                              // 0..7
    MftahVersion        version;                            // 8..11
    CryptoType          crypto_type;                        // 12..13
    StreamFlags         stream_flags;                       // 14
    char                iv_seed_step;                       // 15
    union {                                                 // 16..79
        char[64]        nonce;
        char[64]        noise;
    }
    // Items below are always ENCRYPTED for MFTAH files.
    uint                wrapper_digest_offset;              // 80..83
    uint                original_digest_offset;             // 84..87
    ulong               payload_start;                      // 88..95
    ulong               payload_length;                     // 96..103
    char                chunk_count;                        // 104
    char[7]             iv_seeds;                           // 105..111
    char[16]            signature;                          // 112..127
    // After the signature, any amount of padding can be used by the protocol depending on the
    //   payload's CryptoType. This is why there's a set of 'offsets' in the above. Some block
    //   ciphers will use this space for other necessary information about the payload. It's up
    //   to each crypto implementation to do so.
}

const HEADER_ENCRYPT_OFFSET = 80; //$offsetof(P.payload_length);
const HEADER_ENCRYPT_LENGTH = PayloadHeader.sizeof - HEADER_ENCRYPT_OFFSET;


// TODO: Do I need this?
macro @w($str) @const
{
    $if $defined(MFTAH_WIDESTR) :
        return $$wstr16($str);
    $else
        return $str;
    $endif
}


// Individual KeyDigestProvier types are defined in a separate location, but are referenced in this file.
interface KeyDigestProvider
{
    fn char[] digest(char[]);
}

// Individual CryptoProvider types are defined in a separate location, but are referenced in this file.
interface CryptoProvider
{
    fn char[] encrypt_mut(char[], ...);
    fn char[] decrypt_mut(char[], ...);
}


struct Payload
{
    HooksTable          hooks;

    PayloadHeader*      header_start;
    void*               data_start;
    ulong               data_length;
    char                expected_num_chunks;

    bool                is_streamed;
    PayloadState        state;

    char[]              w_digest;
    char[]              o_digest;

    char[]              current_iv;

    ulong               processed_bytes_counter;
}


fn void? Payload.init(&self, HooksTable hooks)
{
    //
}


fn char[]? Payload.generate_random_data(&self, usz length) @local
{
    //
}


fn void? Payload.refresh_state(&self) @local
{
    //
}


fn char[]? Payload.digest_key(&self) @local
{
    //
}


fn char[]? Payload.make_authentication_digest(&self, char[] input) @local
{
    //
}


fn bool? Payload.try_key(&self, char[] key)
{
    //
}


fn void? Payload.encrypt(&self)
{
    //
}


fn void? Payload.decrypt(&self)
{
    //
}


fn void? Payload.flush(&self, usz requested_callback_block_size)
{
    //
}
