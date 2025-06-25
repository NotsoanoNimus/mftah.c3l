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
    PAYLOAD_ALREADY_INITIALIZED,
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
    BAD_NONCE,
    BAD_NONCE_SEEDS,
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
    char[]              input;
    WorkType            work_type;
    CryptoType          crypto_type;
    uint                thread_index;
    bool                suppress_progress;
}


const HEADER_ENCRYPT_OFFSET = 80; //$offsetof(P.payload_length);
const HEADER_ENCRYPT_LENGTH = PayloadHeader.sizeof - HEADER_ENCRYPT_OFFSET;

const char[] HEADER_SIGNATURE   = "_MFTAH_UNLOCKED_"[:16];
const char[] HEADER_MAGIC       = "MFTAHFMT"[:8];

const NONCE_LEN = 64;   // technically a "max" len
const SEEDS_COUNT = 7;


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
    char                nonce_seed_step;                    // 15
    union
    {                                                       // 16..79
        char[NONCE_LEN] nonce;
        char[NONCE_LEN] noise;
    }
    // Items below are always ENCRYPTED for MFTAH files.
    uint                wrapper_digest_offset;              // 80..83
    uint                original_digest_offset;             // 84..87
    ulong               payload_start;                      // 88..95
    ulong               payload_length;                     // 96..103
    char                chunk_count;                        // 104
    char[SEEDS_COUNT]   nonce_seeds;                        // 105..111
    char[16]            signature;                          // 112..127
    // After the signature, any amount of padding can be used by the protocol depending on the
    //   payload's CryptoType. This is why there's a set of 'offsets' in the above. Some block
    //   ciphers will use this space for other necessary information about the payload. It's up
    //   to each crypto implementation to do so.
}


// TODO: Do I need this?
macro @w($str) @const
{
    $if $defined(MFTAH_WIDESTR) :
        return $$wstr16($str);
    $else
        return $str;
    $endif
}


// Implementing KeyDigestProvier types are defined in a separate location, but are referenced in this file.
interface DigestProvider
{
    fn char[] digest(char[]);
}

// Implementing CryptoProvider types are defined in a separate location, but are referenced in this file.
interface CryptoProvider
{
    fn char[] encrypt_mut(char[], ...);
    fn char[] decrypt_mut(char[], ...);
}


struct Payload
{
    bool                is_initialized;

    HooksTable          hooks;

    Xoshiro256pp        prng;

    PayloadHeader*      header_start;
    char[]              data;
    char                expected_num_chunks;

    bool                is_streamed;
    PayloadState        state;

    char[]              w_digest;
    char[]              o_digest;

    char[]              key;

    char[]              current_nonce;
    ulong               nonce_rotation_counter;
    ulong               processed_bytes_counter;
}


<*
 * Initialize the Payload meta-object with details about a buffer of
 *   data, whether a full payload or the first block of a stream.
 *
 * @param [in] hooks : "A set of function pointers for the MFTAH payload to utilize during operations."
 *>
fn void? Payload.init(&self, HooksTable hooks)
{
    if (self.is_initialized) return PAYLOAD_ALREADY_INITIALIZED?;

    // ...

    self.is_initialized = true;
}


<*
 * Scramble select fields of the Payload with the attached PRNG, then zero the structure.
 *>
fn void Payload.destroy(&self)
{
    if (!self.is_initialized) return;

    for (usz i = 0; i < self.key.len; ++i) self.key[i] = (char)(self.prng.next());
    for (usz i = 0; i < PayloadHeader.sizeof; ++i) self.header_start[i] = (char)(self.prng.next());

    for (i = 0; i < Payload.sizeof; ++i) ((char*)self)[i] = 0;
    for (i = 0; i < Payload.sizeof; ++i) ((char*)self)[i] = 0;
    for (i = 0; i < Payload.sizeof; ++i) ((char*)self)[i] = 0;

    self.is_initialized = false;
}


<*
 *
 *>
fn void? Payload.create_from(&self, char[] data_buffer, Fn CryptoType crypto_type, ulong header_spacing = 0, ulong extra_padding = 0)
{
    //
}


alias FnStreamReadNextBlock = fn char[] ();

fn void? Payload.stream_from(&self, FnStreamReadNextBlock next_block_callback, ulong header_spacing = 0, ulong extra_padding = 0)
{
    // basically, read the callback until len == 0, then pass the accumulated char[] buffer to 'create_from', but make sure to indicate 'stream' mode
    //    indicating 'stream' mode is actually CRUCIAL for the encryption/decryption to succeed for mixing nonces.
    self.is_streamed = true;
}


<*
 * Use an initialized PRNG instance (attached to the Payload wrapper)
 *   to generate a byte array of randomized values to consume.
 *
 * @param [&inout] destination : "The mutable destination slice where generated bytes are sequentially stored."
 * @param [in] length : "How many bytes of data to generate and return."
 *
 * @require destination.len >= length : "The requested length cannot be larger than the destination slice's length."
 *>
fn void Payload.generate_random_data(&self, char[] destination, usz length) @local
{
    if (0 == length) return;

    for (usz i = 0; i < length; ++i) destination[i] = (char)(self.prng.next() & 0xFF);
}


<*
 * Rotate the nonce/initialization-vector to its next value. This usually occurs
 *   as part of a change to the next 'chunk' of a payload. This doesn't use any
 *   tricks beyond a chain of XORs and an occasional message digest to prevent
 *   periodic data from appearing in many-chunk payloads.
 *>
fn void? Payload.next_nonce(&self) @local
{
    defer self.nonce_rotation_counter++;

    // If the rotation counter is a multiple of two passes-worth over the set of IV/nonce seeds,
    //   then use the designated digest function to change the nonce value around entirely.
    ulong constrained_counter = (self.nonce_rotation_counter + 1) % (2 + (2 * SEEDS_COUNT));

    if (0 == constrained_counter) {
        self.current_nonce = self.make_authentication_digest()[:self.current_nonce.len];

        return;
    }

    // Otherwise, just mix the current nonce with an XOR step, using nonce_seed values and the public 'stepper'.
    //
}


<*
 * Examine the fields of the pointed-to header and populate all necessary Payload
 *   fields as if the payload is being read for the first time. This occurs when
 *   the state of some already-loaded data might be changed and needs to be changed
 *   once more (e.g., rekeying operations).
 *>
fn void? Payload.refresh_state(&self) @local
{
    if (null == self.header_start) return MISSING_PAYLOAD?;
}


<*
 * Based on the payload's CryptoType, return a message digest (hash/hmac/etc) of the current key.
 *>
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
