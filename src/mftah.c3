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

import mftah::util @public;


enum MftahVersion : uint (char major, char minor, ushort release)
{
    INITIAL_RELEASE         = { 1, 0, 0 },
    DYNAMIC_CRYPTO          = { 2, 0, 512 }
}
const MftahVersion CURRENT_VERSION = DYNAMIC_CRYPTO;

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
    NOT_YET_IMPLEMENTED,
    NOT_INITIALIZED,
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
const char[] HEADER_MAGIC       = "MFTAHENC"[:8];

const NONCE_LEN = 64;   // technically a "max" len
const SEEDS_COUNT = 7;


bitstruct StreamFlags : char
{
    bool                enabled     : 0;
    bool                canary      : 1;
    char                size_factor : 2..7;
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


// Implementing KeyDigestProvier types are defined in a separate location, but are referenced in this file.
interface DigestProvider
{
    fn char[] iface_digest(char[]);

    fn void iface_init();
    fn void iface_update(char[]);
    fn char[] iface_final();
}

interface HmacDigestProvider
{
    fn char[] iface_digest(char[], char[]);

    fn void iface_init(char[]);
    fn void iface_update(char[]);
    fn char[] iface_final();
}

// Implementing CryptoProvider types are defined in a separate location, but are referenced in this file.
interface CryptoProvider
{
    fn char[] encrypt_mut(char[], ...);
    fn char[] decrypt_mut(char[], ...);
}


struct Payload
{
    bool                is_initialized;   // track whether 'init' has been called for the instance yet

    HooksTable          hooks;   // function pointer table to use for common libc/os-specific (like 'malloc')

    Xoshiro256pp        prng;   // random number generator attached to the instance.

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

    DigestProvider      digest_service;
    HmacDigestProvider  o_hmac_service;
    HmacDigestProvider  w_hmac_service;
    CryptoProvider      crypto_service;
}


<*
 * Perform the most basic initialization of a payload header possible for a new payload. This is essentially
 *   a process of adding in all signatures and setting to-be-filled data bits to 1. This process ensures that
 *   fields like the 'stream canary' can be purposefully turned off to indicate a set value.
 *>
macro PayloadHeader* @init_header(#phdr) @local
{
    usz i = 0;

    Xoshiro256pp prng @noinit;
    prng.init();

    for (i = 0; i < HEADER_MAGIC.len; ++i) #phdr.magic[i] = HEADER_MAGIC[i];
    for (i = 0; i < HEADER_SIGNATURE.len; ++i) #phdr.signature[i] = HEADER_SIGNATURE[i];

    *((ushort*)(&#phdr.crypto_type)) = (ushort)0xFFFF;
    #phdr.stream_flags = (StreamFlags)(char)0xFF;

    for (i = 0; i < NONCE_LEN; ++i) #phdr.nonce[i] = (char)(prng.next() & 0xFF);

    for (i = 0; i < SEEDS_COUNT; ++i) #phdr.nonce_seeds[i] = (char)(prng.next() & 0xFF);
    #phdr.nonce_seed_step = (char)(prng.next() & 0xFF);

    #phdr.version = CURRENT_VERSION;

    #phdr.wrapper_digest_offset     = 0xFFFF_FFFF;
    #phdr.original_digest_offset    = 0xFFFF_FFFF;
    #phdr.payload_start             = 0xFFFF_FFFF_FFFF_FFFF;
    #phdr.payload_length            = 0xFFFF_FFFF_FFFF_FFFF;
    #phdr.chunk_count               = 0xFF;

    return #phdr;
}


<*
 * Initialize the Payload meta-object with details about a buffer of
 *   data, whether a full payload or the first block of a stream.
 *
 * @param [in] hooks : "A set of function pointers for the MFTAH payload to utilize during operations."
 *>
fn void? Payload.init(&self, HooksTable hooks, CryptoType crypto_type)
{
    if (self.is_initialized) return PAYLOAD_ALREADY_INITIALIZED?;

    // ...

    self.prng.init();

    util::@set_payload_services(
        crypto_type, hooks.malloc, self.digest_service, self.o_hmac_service,
        self.w_hmac_service, self.crypto_service)!;

    self.is_initialized = true;
}


<*
 * Scramble select fields of the Payload with the attached PRNG, then zero the structure.
 *>
fn void? Payload.destroy(&self) @local @maydiscard
{
    if (!self.is_initialized) return NOT_INITIALIZED?;

    usz i;

    for (i = 0; i < self.key.len; ++i) self.key[i] = (char)(self.prng.next());
    for (i = 0; i < PayloadHeader.sizeof; ++i) ((char*)self.header_start)[i] = (char)(self.prng.next());

    self.hooks.free(self.digest_service);
    self.hooks.free(self.o_hmac_service);
    self.hooks.free(self.w_hmac_service);
    self.hooks.free(self.crypto_service);

    for (i = 0; i < Payload.sizeof; ++i) ((char*)self)[i] = 0;
    for (i = 0; i < Payload.sizeof; ++i) ((char*)self)[i] = 0;
    for (i = 0; i < Payload.sizeof; ++i) ((char*)self)[i] = 0;

    self.is_initialized = false;
}


<*
 *
 *>
fn void? Payload.create_from(&self, char[] data_buffer, CryptoType crypto_type, ulong header_spacing = 0, ulong extra_padding = 0)
{
    //
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
        self.current_nonce =
            self.make_authentication_digest(self.current_nonce)[:self.current_nonce.len]!;

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
    return NOT_YET_IMPLEMENTED?;
}


<*
 * As opposed to hashing/KDF'ing the connected 'key' value, generate an authentication digest
 *   with the key. Some algorithms may use, e.g., PBKDF2 to get a password digest, while using
 *   HMAC_SHA256 to make an authenticated MAC for the payload itself.
 *
 * @require input.len > 0 : "Input field cannot have empty contents."
 *>
fn char[]? Payload.make_authentication_digest(&self, char[] input) @local
{
    return NOT_YET_IMPLEMENTED?;
}


<*
 * //
 *>
fn bool? Payload.try_key(&self, char[] key)
{
    return NOT_YET_IMPLEMENTED?;
}


<*
 * //
 *>
fn void? Payload.encrypt(&self)
{
    return NOT_YET_IMPLEMENTED?;
}


<*
 * //
 *>
fn void? Payload.decrypt(&self)
{
    return NOT_YET_IMPLEMENTED?;
}


<*
 * //
 *>
fn void? Payload.flush(&self, usz requested_callback_block_size)
{
    return NOT_YET_IMPLEMENTED?;
}


alias FnStreamReadNextBlock = fn char[] ();
alias FnStreamYieldBlock = FnYield;

const MIN_STREAM_BLOCK_SIZE_FACTOR = 1;
const MAX_STREAM_BLOCK_SIZE_FACTOR = 16;

struct MftahStreamContext
{
    HooksTable hooks;
    char[] key;
    char block_size_factor;
    FnStreamReadNextBlock next_block_callback;
    FnStreamYieldBlock yield_callback;
}

<*
 * @require context.block_size_factor >= MIN_STREAM_BLOCK_SIZE_FACTOR : "Block size factor cannot be smaller than 1 (16 MiB)."
 * @require context.block_size_factor <= MAX_STREAM_BLOCK_SIZE_FACTOR : "Block size factor cannot be greater than 16 (256 MiB)."
 *>
fn void? stream_new(MftahStreamContext context, CryptoType crypto_type)
{
    ulong stream_block_size = ((ulong)context.block_size_factor << 4) * (1024 * 1024);

    Payload p;
    p.init(context.hooks, crypto_type)!;

    // Initialize pw hasher, HMAC, and crypto services.
    p.digest_service.iface_init();
    p.o_hmac_service.iface_init(context.key);
    p.w_hmac_service.iface_init(context.key);
    // p.crypto_service.iface_init();

    // Set up the constructed payload header. A streamed MFTAH payload consists of a 'start' header and a 'tail' header.
    //   The former has most of the base payload information present, but fills out o_hmac, w_hmac
    p.header_start = context.hooks.malloc(PayloadHeader.sizeof);
    if (null == p.header_start) return OUT_OF_RESOURCES?;

    PayloadHeader* hdr = @init_header(p.header_start);
    hdr.crypto_type = crypto_type;
    hdr.stream_flags = { .enabled = true, .canary = false, .size_factor = context.block_size_factor };

    // Encrypt the start header at the encryption boundary.

    // Set up the encryption buffer.
    void* working_buffer = context.hooks.calloc(1, stream_block_size);
    if (null == working_buffer) return OUT_OF_RESOURCES?;

    char[] buff = ((char*)working_buffer)[:stream_block_size];
    defer {
        context.hooks.memset(buff.ptr, 0x00, stream_block_size);
        context.hooks.free(buff.ptr);
    }

    // basically, read the callback until len == 0, then pass the accumulated char[] buffer to 'create_from', but make sure to indicate 'stream' mode
    //    indicating 'stream' mode is actually CRUCIAL for the encryption/decryption to succeed for mixing nonces.
    // ^ NOT TRUE -- the point of 'streaming' is to reduce the memory usage of the format to a single chunk size.
    //                The stream functionality itself must operate through a single while-loop where the chunked input is being read...

    // Might be best to use single-entry 'stream_create' and 'stream_decrypt' module-level functions for this.

    // Pull in the data w/ 'next_block', manipulate it however necessary, then call 'yield' to 'submit' the manipulated data to the next part of the pipeline.

    // ...

    //self.is_streamed = true;
}


fn void? stream_decrypt(MftahStreamContext context)
{
    // while (next_block.len) ... next_block = next_block_callback();

    // while (data_ptr != end_ptr) yield_callback(block[..]);
}
