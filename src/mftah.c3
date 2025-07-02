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
import mftah::threading;


struct MftahVersion @packed
{
    char major;
    char minor;
    ushort release;
}

const MftahVersion INITIAL_RELEASE  = { 1, 0, 0 };
const MftahVersion DYNAMIC_CRYPTO   = { 2, 2, 0x222 };

const MftahVersion CURRENT_VERSION = DYNAMIC_CRYPTO;


enum MftahCryptoType : const ushort
{
    AES_256_CBC_HMAC_SHA256     = 1,
    CHACHA20_POLY1305           = 2,
}


faultdef
    NOT_YET_IMPLEMENTED,
    NOT_INITIALIZED,
    PAYLOAD_ALREADY_INITIALIZED,
    OUT_OF_RESOURCES,
    INVALID_STREAM_BLOCK_SIZE,
    MISALIGNED_STREAM_BLOCK_SIZE,
    MISSING_PAYLOAD_HEADER,
    INVALID_PAYLOAD_PADDING,
    PAYLOAD_NOT_PADDED,
    INVALID_PAYLOAD_MAGIC,
    INVALID_CRYPTO_TYPE,
    PAYLOAD_NOT_STREAMED,
    INCORRECT_KEY,
    PREMATURE_END_OF_STREAM,
    STREAM_MISSING_POST_HEADER,
    BAD_WRAPPER_HMAC,
    BAD_ORIGINAL_HMAC,
    BAD_SEED_STEP_VALUE
    ;


const HEADER_ENCRYPT_OFFSET = 80; //$offsetof(P.payload_length);
const HEADER_ENCRYPT_LENGTH = PayloadHeader.sizeof - HEADER_ENCRYPT_OFFSET;

const char[] HEADER_SIGNATURE   = "_MFTAH_UNLOCKED_"[:16];
const char[] HEADER_MAGIC       = "MFTAHENC"[:8];

const NONCE_LEN = 64;   // technically a "max" len
const SEEDS_COUNT = 7;


bitstruct MftahStreamFlags : char
{
    bool                enabled     : 0;
    bool                canary      : 1;
    char                size_factor : 2..7;
}

struct PayloadHeader @packed
{
    char[8]             magic;                              // 0..7
    MftahVersion        version;                            // 8..11
    MftahCryptoType     crypto_type;                        // 12..13
    MftahStreamFlags    stream_flags;                       // 14
    char                nonce_seed_step;                    // 15
    char[NONCE_LEN]     nonce;
    // Items below are always ENCRYPTED for MFTAH files.
    uint                original_digest_offset;             // 84..87
    uint                wrapper_digest_offset;              // 80..83
    ulong               payload_start;                      // 88..95
    ulong               payload_length;                     // 96..103
    union
    {                                                       // 104
        char            chunk_count;
        char            roll_interval;
    }
    char[SEEDS_COUNT]   nonce_seeds;                        // 105..111
    char[16]            signature;                          // 112..127
    // After the signature, any amount of padding can be used by the protocol depending on the
    //   payload's CryptoType. This is why there's a set of 'offsets' in the above. Some block
    //   ciphers will use this space for other necessary information about the payload. It's up
    //   to each crypto implementation to do so. By default, the actual header gets an extra 80
    //   bytes to bring the sizeof - ENCRYPT_OFFSET value to 128, which will be an even block size
    //   for almost any block cipher.
    char[80]            extra_space;
}


// Implementing KeyDigestProvier types are defined in a separate location, but are referenced in this file.
interface DigestProvider
{
    fn char* iface_digest(char[]);

    fn void iface_init();
    fn void iface_update(char[]);
    fn char* iface_final();

    fn usz iface_hashlen();
}

interface HmacDigestProvider
{
    fn char[] iface_digest(char[], char[]);

    fn void iface_init(char[]);
    fn void iface_update(char[]);
    fn char[] iface_final();

    fn usz iface_hashlen();
}

// Implementing CryptoProvider types are defined in a separate location, but are referenced in this file.
interface CryptoProvider
{
    fn void? iface_init(char[], char[]);

    fn char[]? encrypt_mut(char[]);
    fn char[]? decrypt_mut(char[]);

    fn char[]? pad(char[]);
    fn char[]? unpad(char[]);

    fn usz block_size();
    fn usz iv_size();
}


struct WorkOrder @local
{
    char[]              input;
    char[]              digested_key;
    bool                is_encrypt;
    uint                thread_index;
    PayloadHeader*      raw_header;
}


struct MftahContext @local
{
    bool                is_initialized;   // track whether 'init' has been called for the instance yet

    // TODO: Make this an interface? Likely not, but worth looking into.
    Xoshiro256pp        prng;   // random number generator attached to the instance.

    PayloadHeader*      header_start;

    DigestProvider      digest_service;
    HmacDigestProvider  o_hmac_service;
    HmacDigestProvider  w_hmac_service;
    CryptoProvider      crypto_service;
}


<*
Perform the most basic initialization of a payload header possible for a new payload. This is essentially
  a process of adding in all signatures and setting to-be-filled data bits to 1. This process ensures that
  fields like the 'stream canary' can be purposefully turned off to indicate a set value.
*>
macro PayloadHeader* @init_header(#phdr) @local
{
    usz i = 0;

    Xoshiro256pp prng @noinit;
    prng.init();

    for (i = 0; i < HEADER_MAGIC.len; ++i) #phdr.magic[i] = HEADER_MAGIC[i];
    for (i = 0; i < HEADER_SIGNATURE.len; ++i) #phdr.signature[i] = HEADER_SIGNATURE[i];

    *((ushort*)(&#phdr.crypto_type)) = (ushort)(prng.next() & 0xFFFF);
    #phdr.stream_flags = (MftahStreamFlags)(char)0xFF;

    for (i = 0; i < NONCE_LEN; ++i) #phdr.nonce[i] = (char)(prng.next() & 0xFF);

    for (i = 0; i < SEEDS_COUNT; ++i) #phdr.nonce_seeds[i] = (char)(prng.next() & 0xFF);


    // Prevent divide-by-zero crashes.
    #phdr.nonce_seed_step = (char)(prng.next() & 0xFF);
    if (0 == #phdr.nonce_seed_step) #phdr.nonce_seed_step = (char)(prng.next() & 0xFF) | 0x01;

    for (i = 0; i < 80; ++i) #phdr.extra_space[i] = (char)(prng.next() & 0xFF);

    #phdr.version = CURRENT_VERSION;

    #phdr.wrapper_digest_offset     = (uint)(prng.next() & 0xFFFF_FFFF);
    #phdr.original_digest_offset    = (uint)(prng.next() & 0xFFFF_FFFF);
    #phdr.payload_start             = prng.next() & 0xFFFF_FFFF_FFFF_FFFF;
    #phdr.payload_length            = prng.next() & 0xFFFF_FFFF_FFFF_FFFF;

    // Every roll_interval (between 4 and 12) for streamed payloads causes the IV to be hashed and
    //   the CryptoProvider to be re-initialized. This number is discarded for static/non-streamed payloads.
    #phdr.roll_interval             = ((char)(prng.next() & 0xFF) % ((12+1) - 4)) + 4;

    return #phdr;
}


<*
Assign implementors to each given interface pointer expression, based on the selected crypto type/suite.
*>
macro void? @set_payload_services(
    MftahCryptoType crypto_type, #hash, #o_hmac, #w_hmac, #crypto)
{
    switch (crypto_type) {
        case AES_256_CBC_HMAC_SHA256:
            Sha256* h = malloc(Sha256.sizeof);          #hash = h;
            HmacSha256* ho = malloc(HmacSha256.sizeof); #o_hmac = ho;
            HmacSha256* hw = malloc(HmacSha256.sizeof); #w_hmac = hw;
            AesCtx* c = malloc(AesCtx.sizeof);          #crypto = c;

        case CHACHA20_POLY1305:
            Sha512* h = malloc(Sha512.sizeof);          #hash = h;
            Poly1305* ho = malloc(Poly1305.sizeof);     #o_hmac = ho;
            Poly1305* hw = malloc(Poly1305.sizeof);     #w_hmac = hw;
            ChaCha20* c = malloc(ChaCha20.sizeof);      #crypto = c;

        default: return mftah::INVALID_CRYPTO_TYPE?;
    }
}

macro CryptoProvider? @get_crypto_service(crypto_type)
{
    switch (crypto_type) {
        case AES_256_CBC_HMAC_SHA256: return (AesCtx*)malloc(AesCtx.sizeof);
        case CHACHA20_POLY1305: return (ChaCha20*)malloc(ChaCha20.sizeof);
        default: return mftah::INVALID_CRYPTO_TYPE?;
    }
}

macro DigestProvider? @get_digest_service(crypto_type)
{
    switch (crypto_type) {
        case AES_256_CBC_HMAC_SHA256: return (Sha256*)malloc(Sha256.sizeof);
        case CHACHA20_POLY1305: return (Sha512*)malloc(Sha512.sizeof);
        default: return mftah::INVALID_CRYPTO_TYPE?;
    }
}


<*
Initialize the MFTAH context with details about a buffer of
  data, whether a full payload or the first block of a stream.

@param crypto_type : "The Crypto type used to work on the MFTAH Payload."
*>
fn void? MftahContext.init(&self, MftahCryptoType crypto_type)
{
    if (self.is_initialized) return PAYLOAD_ALREADY_INITIALIZED?;

    self.prng.init();

    @set_payload_services(
        crypto_type,
        self.digest_service,
        self.o_hmac_service,
        self.w_hmac_service,
        self.crypto_service
    )!;

    self.is_initialized = true;
}


<*
Scramble select fields of the Payload with the attached PRNG, then zero the structure.
*>
fn void? MftahContext.destroy(&self) @local @maydiscard
{
    if (!self.is_initialized) return NOT_INITIALIZED?;

    free(self.digest_service);
    free(self.o_hmac_service);
    free(self.w_hmac_service);
    free(self.crypto_service);

    self.is_initialized = false;
}


<*
Use an initialized PRNG instance (attached to the MftahContext wrapper)
  to generate a byte array of randomized values to consume.

@param [out] destination : "The mutable destination slice where generated bytes are sequentially stored."
@param length : "How many bytes of data to generate and return."

@require destination.len >= length : "The requested length cannot be larger than the destination slice's length."
*>
fn void MftahContext.generate_random_data(&self, char[] destination, usz length) @local
{
    if (0 == length) return;

    for (usz i = 0; i < length; ++i) destination[i] = (char)(self.prng.next() & 0xFF);
}


fn void* thread_crypt(void* context) @local
{
    WorkOrder* order = context;

    CryptoProvider crypto_service = @get_crypto_service(order.raw_header.crypto_type)!!;
    defer free(crypto_service);
    DigestProvider digest_service = @get_digest_service(order.raw_header.crypto_type)!!;
    defer free(digest_service);

    usz iv_size = crypto_service.iv_size();
    crypto_service.iface_init(order.digested_key, order.raw_header.nonce[:iv_size])!!;

    // Local nonce updates based on thread_index..
    char[] prev_hash = {};
    char[] current_iv = order.raw_header.nonce[:iv_size];
    defer free(current_iv.ptr);

    for (usz i = 0; i < (order.thread_index + 1); ++i) {
        current_iv = digest_service.iface_digest(i == 0 ? current_iv : prev_hash)[:iv_size];
        if (prev_hash.ptr) free(prev_hash.ptr);
        prev_hash = current_iv;
    }

    if (order.is_encrypt) {
        crypto_service.encrypt_mut(order.input)!!;
    } else {
        crypto_service.decrypt_mut(order.input)!!;
    }

    return null;
}

import std::io;
<*
Encrypt a static, in-memory MFTAH payload from a char slice.

@param [inout] payload : "The heap-allocated input data to encrypt in-place."
@param [in] key : "The symmetric key to use when encrypting the payload."
@param crypto_type : "The predefined MFTAH crypto algorithm suite used to encrypt (and thus decrypt) the payload."
@param thread_count : "The amount of simultaneous threads - or parallel crypto operations - to use when encrypting the payload."
@param payload_start_offset : "How many randomized bytes to insert between the end of the MFTAH payload's new header and the start of the encrypted payload."

@require payload.len > 0 : "The payload cannot be empty."
@require key.len > 0 : "The key cannot be empty."
@require thread_count > 0 && thread_count <= 64 : "The thread count must be at least 1, but not more than 64."
@require payload_start_offset < (16*1024*1024) : "Payload start offset cannot be more than 16 MiB from the end of the header."

@return "A slice pointing to the new, encrypted MFTAH payload details."
*>
fn char[]? new(char[] payload, char[] key, MftahCryptoType crypto_type = CHACHA20_POLY1305,
    char thread_count = 1, ulong payload_start_offset = 0)
{
    MftahContext ctx;
    ctx.init(crypto_type)!;
    defer ctx.destroy();

    // Set up the constructed payload header. A streamed MFTAH payload consists of a 'start' header and a 'tail' header.
    //   The former has most of the base payload information present, but fills out o_hmac, w_hmac, etc. with 0xFF bytes.
    //   The payload allocation is extended a bit to align the distance from the ENCRYPT_OFFSET to the end to 128 bytes.
    ctx.header_start = malloc(PayloadHeader.sizeof);
    if (null == ctx.header_start) return OUT_OF_RESOURCES?;

    PayloadHeader* hdr = @init_header(ctx.header_start);
    defer free(hdr);

    // Store sizes from provider interfaces (these calls can get expensive).
    usz digest_size = ctx.digest_service.iface_hashlen();
    usz block_size = ctx.crypto_service.block_size();
    usz iv_size = ctx.crypto_service.iv_size();
    usz o_hmac_size = ctx.o_hmac_service.iface_hashlen();
    usz w_hmac_size = ctx.w_hmac_service.iface_hashlen();
io::printf("=== SIZES : digest(%d) / block(%d) / iv(%d) / O-HMAC(%d) / W-HMAC(%d)\n", digest_size, block_size, iv_size, o_hmac_size, w_hmac_size);

    // Initialize services.
    ctx.digest_service.iface_init();
    char[] digested_key = ctx.digest_service.iface_digest(key)[:digest_size];
    defer free(digested_key.ptr);
io::printn("digested_key:"); util::@slicedump(digested_key);

    ctx.o_hmac_service.iface_init(digested_key);
    ctx.w_hmac_service.iface_init(digested_key);
    ctx.crypto_service.iface_init(digested_key, hdr.nonce[:iv_size])!;

    // Adjust for extra leading space required by the payload.
    ulong required_hmac_space = o_hmac_size;
    ulong block_padding = ($offsetof(hdr.extra_space) + required_hmac_space) % block_size
        ? (block_size - (($offsetof(hdr.extra_space) + required_hmac_space) % block_size))
        : 0;
    long extra_length_needed = (required_hmac_space + block_padding) - hdr.extra_space.len;
    if (extra_length_needed < 0) extra_length_needed = 0;
io::printf("=== SPACE : required_hmac_space(%d) / block_padding(%d) / extra_length_needed(%d) / ", required_hmac_space, block_padding, extra_length_needed);

    // The 'leader' is the header + extra + W-HMAC space, BEFORE the extra padding requested by the user.
    ulong leader_length = PayloadHeader.sizeof + extra_length_needed + w_hmac_size;
io::printf("leader_length(%d)\n", leader_length);

    ctx.header_start = hdr = realloc(hdr, leader_length);
    if (null == hdr) return OUT_OF_RESOURCES?;
    char[] leader = util::@aob(hdr, leader_length);

    // Before padding, fully digest the input payload as-is to create the O-HMAC.
    ctx.o_hmac_service.iface_update(payload);
    char[] o_hmac = ctx.o_hmac_service.iface_final();
    defer free(o_hmac.ptr);
    leader[$offsetof(hdr.extra_space) : o_hmac_size] = o_hmac[:o_hmac_size];
io::printn("calculated O-HMAC:"); util::@slicedump(o_hmac);

    // Pad the input payload. For block ciphers, this reallocates the pointer and extends the length.
io::printf("=== PAYLOAD_LEN : original(%d) / ", payload.len);
    payload = ctx.crypto_service.pad(payload)!;
io::printf("padded(%d)\n", payload.len);

    // Adjust this start offset to keep the actual payload on a block_size boundary.
    payload_start_offset = (leader_length + payload_start_offset) % block_size
        ? (payload_start_offset + (block_size - ((leader_length + payload_start_offset) % block_size)))
        : payload_start_offset;

    ulong payload_start = leader_length + payload_start_offset;
    ulong payload_length = payload.len;
io::printf("=== MEASUREMENTS : payload_start_offset(%d) / payload_start(%d) / payload_length(%d) / thread_count(%d) / ",
    payload_start_offset, payload_start, payload_length, thread_count);

    // Set payload fields.
    hdr.crypto_type = crypto_type;
    hdr.stream_flags.enabled = false;
    hdr.stream_flags.canary = true;
    hdr.stream_flags.size_factor = 0;
    hdr.original_digest_offset = $offsetof(hdr.extra_space);
    hdr.wrapper_digest_offset = (uint)leader_length - (uint)w_hmac_size;
    hdr.payload_start = payload_start;
    hdr.payload_length = payload_length;
    hdr.chunk_count = thread_count;

    ulong full_encrypted_length = payload_start + payload_length;
io::printf("full_encrypted_length(%d)\n", full_encrypted_length);

    // Create the resultant payload container from the original pointer (through realloc).
    PayloadHeader* enc_hdr = realloc(payload.ptr, full_encrypted_length);
    if (null == enc_hdr) return OUT_OF_RESOURCES?;
    // defer free(enc_hdr);   // NOTE: this frees the whole payload pointer, so it's not done...
    payload = util::@aob(enc_hdr, full_encrypted_length);
    payload[payload_start..] = payload[:payload_length];   // move the original payload contents up to the start within the buffer
    payload[:leader_length] = leader[..];

    // Encrypt the start header at the encryption boundary.
    // *enc_hdr = *hdr;
    ctx.crypto_service.encrypt_mut(payload[HEADER_ENCRYPT_OFFSET : HEADER_ENCRYPT_LENGTH + extra_length_needed])!;

    // Randomize data between W-HMAC end and start of payload.
    if (payload_start_offset > 0) {
        for (usz i = 0; i < payload_start_offset; ++i) payload[leader_length + i] = (char)(ctx.prng.next() & 0xFF);
    }

    // W-HMAC: Consume the header up to the payload start.
    ctx.w_hmac_service.iface_update(payload[:hdr.wrapper_digest_offset]);

    // Time to vectorize encryption. Since IVs get mixed and aren't reused, this even works with something like AES-CBC!
    Pthread_t[] thread_pool = ((Pthread_t*)calloc(Pthread_t.sizeof * thread_count))[:thread_count];
    if (null == thread_pool.ptr) return OUT_OF_RESOURCES?;
    defer free(thread_pool);

    WorkOrder*[] work_orders = ((WorkOrder**)calloc(WorkOrder*.sizeof * thread_count))[:thread_count];
    if (null == work_orders.ptr) return OUT_OF_RESOURCES?;
    defer free(work_orders);

    ulong schedule_remaining_length = payload_length;
    ulong schedule_span = (payload_length / thread_count);

    // When the size of each scheduled thread's content is 0, too many threads were requested so just use one.
    if (!schedule_span) {
        schedule_span = payload_length;
        thread_count = 1;
    }

    for (uint thread = 0; thread < thread_count; ++thread) {
        work_orders[thread] = malloc(WorkOrder.sizeof);
        if (null == work_orders[thread]) return OUT_OF_RESOURCES?;

        *(work_orders[thread]) = {
            .input = payload[
                (payload_start + (thread * schedule_span))
                : ((thread + 1) == thread_count ? schedule_remaining_length : schedule_span)
            ],
            .digested_key = digested_key,
            .is_encrypt = true,
            .thread_index = thread,
            .raw_header = enc_hdr,
        };

        (void)threading::pthread_create(&thread_pool[thread], null, &thread_crypt, work_orders[thread]);

        schedule_remaining_length -= schedule_span;
    }

    // Await all threads.
    for (usz thread = 0; thread < thread_count; ++thread) {
        (void)threading::pthread_join(thread_pool[thread], null);
        free(work_orders[thread]);
    }

    // W-HMAC: Consume the rest of the payload. The W-HMAC is set 'in the clear' on the payload header.
    ctx.w_hmac_service.iface_update(payload[leader_length..]);
    char[] w_hmac = ctx.w_hmac_service.iface_final();
    defer free(w_hmac.ptr);
    payload[hdr.wrapper_digest_offset : w_hmac_size] = w_hmac[:w_hmac_size];

    // All done!
    return payload;
}


<*
Decrypt a static, in-memory MFTAH payload from a char slice.

@param [inout] payload : "The input MFTAH payload to be decrypted and stripped of header information."
@param [in] key : "The key used to decrypt the MFTAH payload."

@require payload.len > 0 : "The payload cannot be empty."
@require key.len > 0 : "The key cannot be empty."
*>
fn void? decrypt(char[] payload, char[] key)
{
    //
}


alias FnStreamReadNextBlock = fn char[] (usz);
alias FnStreamYieldBlock = fn void (char[]);

const MIN_STREAM_BLOCK_SIZE_FACTOR = 1;
const MAX_STREAM_BLOCK_SIZE_FACTOR = 16;


<*
Create a new streamed MFTAH payload from a series of input data that's both read and written in chunks.

@param [in] key : "The raw key used to encrypt the new MFTAH payload."
@param crypto_type : "The crypto type used to encrypt the new MFTAH payload."
@param block_size_factor : "Controls the approximate stream block size: a memory chunk allocated for revolving in/out data."
@param next_block_callback : "A function which provides a slice pointer to the next block of plaintext input data."
@param yield_callback : "A function which accepts encrypted stream data in chunks, to store to disk or offload elsewhere."

@require block_size_factor >= MIN_STREAM_BLOCK_SIZE_FACTOR : "Block size factor cannot be smaller than 1 (16 MiB)."
@require block_size_factor <= MAX_STREAM_BLOCK_SIZE_FACTOR : "Block size factor cannot be greater than 16 (256 MiB)."
*>
fn void? stream_new(char[] key, MftahCryptoType crypto_type, char block_size_factor,
    FnStreamReadNextBlock next_block_callback, FnStreamYieldBlock yield_callback)
{
    ulong stream_block_size = (((ulong)block_size_factor << 4) + 1) * (1024 * 1024);
    ulong bytes_counter = 0;
    ulong block_counter = 0;
    ulong original_payload_length = 0;
    char seed_step_counter = 0;

    MftahContext ctx;
    ctx.init(crypto_type)!;
    defer ctx.destroy();

    // Set up the constructed payload header. A streamed MFTAH payload consists of a 'start' header and a 'tail' header.
    //   The former has most of the base payload information present, but fills out o_hmac, w_hmac, etc. with 0xFF bytes.
    //   The payload allocation is extended a bit to align the distance from the ENCRYPT_OFFSET to the end to 128 bytes.
    ctx.header_start = malloc(PayloadHeader.sizeof);
    if (null == ctx.header_start) return OUT_OF_RESOURCES?;

    PayloadHeader* hdr = @init_header(ctx.header_start);
    defer free(hdr);

    PayloadHeader* enc_hdr = malloc(PayloadHeader.sizeof);   // copies the 'true' header and gets encrypted
    if (null == enc_hdr) return OUT_OF_RESOURCES?;
    defer free(enc_hdr);

    hdr.crypto_type = crypto_type;
    hdr.stream_flags = { .enabled = true, .canary = false, .size_factor = block_size_factor };
    char[NONCE_LEN] nonce; nonce[..] = hdr.nonce[..];
    seed_step_counter = hdr.nonce_seed_step;

    // Initialize pw hasher, HMAC, and crypto services.
    ctx.digest_service.iface_init();
    char[] digested_key = ctx.digest_service.iface_digest(key)[:ctx.digest_service.iface_hashlen()];
    defer free(digested_key.ptr);

    ctx.o_hmac_service.iface_init(digested_key);
    ctx.w_hmac_service.iface_init(digested_key);
    ctx.crypto_service.iface_init(digested_key, nonce[:ctx.crypto_service.iv_size()])!;

    usz block_size = ctx.crypto_service.block_size();
    usz iv_size = ctx.crypto_service.iv_size();

    // This represents the length of the trailing payload header and the subsequent HMACs.
    usz trailer_size = PayloadHeader.sizeof + ctx.o_hmac_service.iface_hashlen() + ctx.w_hmac_service.iface_hashlen();

    // Encrypt the start header at the encryption boundary.
    //   Any important values should be updated/read from the true, never-emitted header: 'hdr'.
    *enc_hdr = *hdr;
    (void)ctx.crypto_service.encrypt_mut(((char*)enc_hdr)[HEADER_ENCRYPT_OFFSET : HEADER_ENCRYPT_LENGTH])!;

    // The encrypted header should be immediately yielded back to the caller on its own.
    yield_callback(util::@aob(enc_hdr));
    bytes_counter += PayloadHeader.sizeof;

    // Also, update the Wrapper HMAC to consume the initial header.
    ctx.w_hmac_service.iface_update(util::@aob(enc_hdr));

    // Start the loop which reads from the input stream. Read until there's no data left.
    //   Streaming mode DOES NOT roll the nonce because it's a fully synchronous operation.
    bool exit_loop = false;
    char[] this_block;   // make this accessible in the outer scope
    do OUTER: {
        this_block = next_block_callback(stream_block_size);

        // Should always prep to exit the loop when a full stream block wasn't received.
        exit_loop = this_block.len < stream_block_size;

        if (this_block.len > 0) ctx.o_hmac_service.iface_update(this_block);   // consume O-HMAC contents

        // Roll the CryptoProvider and IV when the blocks counter hits the roll_interval.
        if (0 == (block_counter % hdr.roll_interval)) {
            char[] iv_hash = ctx.digest_service.iface_digest(nonce[:iv_size])[:iv_size];
            nonce[:iv_size] = iv_hash[:iv_size];
            free(iv_hash);

            ctx.crypto_service.iface_init(digested_key, nonce[:iv_size])!;
        } else {
            // XOR the nonce/IV with a 'seed' value based on the block counter.
            char which = hdr.nonce_seeds[block_counter % SEEDS_COUNT];

            for (usz i = 0; i < iv_size; ++i) nonce[i] ^= which;

            if (!seed_step_counter) {
                for (usz i = 0; i < iv_size; ++i) nonce[i] ^= hdr.nonce_seed_step;
                seed_step_counter = hdr.nonce_seed_step;
            }

            --seed_step_counter;
        }

        // This intentionally pads data of ANY size up to a block length, because that's how PKCS#7 works!
        //   Note that unit tests will be designed which should cover all these scenarios; i.e., all the
        //   different boundaries, header locations, etc. to ensure nothing is broken.
        if (exit_loop) {
            this_block = ctx.crypto_service.pad(this_block)!;   // NOTE: this reallocates the pointer!
            // ^ that's why this must be the last call to the method...

            // When the final block length would cause the trailing content to fall on a stream block boundary,
            //   return an error that requires the user to choose a different stream block size. This should
            //   be a rare occurrence, but it saves plenty of costs and checks when performing streamed
            //   decryption because the location of the trailing header is guaranteed to be within a block.
            if (this_block.len >= stream_block_size - trailer_size) return MISALIGNED_STREAM_BLOCK_SIZE?;
        }

        ctx.crypto_service.encrypt_mut(this_block)!;   // encrypt
        ctx.w_hmac_service.iface_update(this_block);   // consume W-HMAC contents

        yield_callback(this_block);   // emit
        bytes_counter += this_block.len;   // measure
        ++block_counter;
    } while (!exit_loop);

    free(this_block.ptr);

    original_payload_length = (bytes_counter - PayloadHeader.sizeof);

    // Finalize O-HMAC.
    char[] o_hmac = ctx.o_hmac_service.iface_final();
    defer free(o_hmac.ptr);

    // Update the unencrypted payload header with the proper values.
    //   This is basically just the payload start and length for validation, because everything
    //   else doesn't really matter for streamed payloads.
    hdr.payload_start = PayloadHeader.sizeof;
    hdr.payload_length = original_payload_length;

    // Shadow the header, encrypt the proper portion, and emit it.
    *enc_hdr = *hdr;
    (void)ctx.crypto_service.encrypt_mut(((char*)enc_hdr)[HEADER_ENCRYPT_OFFSET : HEADER_ENCRYPT_LENGTH])!;

    yield_callback(util::@aob(enc_hdr));

    ctx.w_hmac_service.iface_update(util::@aob(enc_hdr));

    // Finally emit the O_HMAC, followed by the finalized W_HMAC.
    yield_callback(o_hmac);
    ctx.w_hmac_service.iface_update(o_hmac);

    char[] w_hmac = ctx.w_hmac_service.iface_final();
    yield_callback(w_hmac);
    free(w_hmac);
}


<*
Decrypt a MFTAH payload which was encrypted using the 'stream' chunking method.

@param [in] key : "The raw key used to decrypt the streamed MFTAH payload."
@param next_block_callback : "A function which provides a slice pointer to the next block of ciphertext input data."
@param yield_callback : "A function which accepts decrypted stream data in chunks, to store to disk or offload elsewhere."
*>
fn void? stream_decrypt(
    char[] key, FnStreamReadNextBlock next_block_callback, FnStreamYieldBlock yield_callback)
{
    // Read in the initial header and make sure this is a valid STREAMED MFTAH PAYLOAD.
    char[] initial_header = next_block_callback(PayloadHeader.sizeof);

    // Validate header fields.
    if (initial_header.len < PayloadHeader.sizeof) return MISSING_PAYLOAD_HEADER?;

    // Copy.
    PayloadHeader* in_hdr = malloc(PayloadHeader.sizeof);
    if (null == in_hdr) return OUT_OF_RESOURCES?;
    defer free(in_hdr);
    *in_hdr = *(PayloadHeader*)initial_header.ptr;

    if (HEADER_MAGIC != util::@aob(in_hdr)[:HEADER_MAGIC.len]) return INVALID_PAYLOAD_MAGIC?;
    if (in_hdr.crypto_type < MftahCryptoType.values[0] || in_hdr.crypto_type > MftahCryptoType.values[^1]) return INVALID_CRYPTO_TYPE?;

    if (!in_hdr.stream_flags.enabled || in_hdr.stream_flags.canary) return PAYLOAD_NOT_STREAMED?;
    if (in_hdr.stream_flags.size_factor < MIN_STREAM_BLOCK_SIZE_FACTOR
        || in_hdr.stream_flags.size_factor > MAX_STREAM_BLOCK_SIZE_FACTOR) return INVALID_STREAM_BLOCK_SIZE?;

    if (0 == in_hdr.nonce_seed_step) return BAD_SEED_STEP_VALUE?;

    // Initialize the 'payload' object.
    MftahContext ctx;
    ctx.init(in_hdr.crypto_type)!;
    defer ctx.destroy();

    char[NONCE_LEN] nonce; nonce[..] = in_hdr.nonce[..];
    char seed_step_counter = in_hdr.nonce_seed_step;

    // Initialize pw hasher, HMAC, and crypto services.
    ctx.digest_service.iface_init();
    char[] digested_key = ctx.digest_service.iface_digest(key)[:ctx.digest_service.iface_hashlen()];
    defer free(digested_key.ptr);

    ctx.o_hmac_service.iface_init(digested_key);
    ctx.w_hmac_service.iface_init(digested_key);
    ctx.crypto_service.iface_init(digested_key, nonce[:ctx.crypto_service.iv_size()])!;

    ulong stream_block_size = (((ulong)in_hdr.stream_flags.size_factor << 4) + 1) * (1024 * 1024);
    ulong bytes_counter = 0;
    ulong block_counter = 0;
    ulong original_payload_length = 0;

    usz block_size = ctx.crypto_service.block_size();
    usz iv_size = ctx.crypto_service.iv_size();

    // W-HMAC consumes the encrypted payload header.
    ctx.w_hmac_service.iface_update(util::@aob(in_hdr));

    // Decrypt the header's encrypted segment and validate that the signature is properly returned.
    //   This is basically a quick initial password check that can save a lot of wasted time.
    (void)ctx.crypto_service.decrypt_mut(util::@aob(in_hdr)[HEADER_ENCRYPT_OFFSET : HEADER_ENCRYPT_LENGTH])!;

    if (HEADER_SIGNATURE != util::@aob(in_hdr)[$offsetof(in_hdr.signature) : HEADER_SIGNATURE.len]) return INCORRECT_KEY?;

    // We need to always preserve a max of the PayloadHeader size's bytes from the trailing end of the last block.
    //   Consider the case where the trailing header falls on the final 10 bytes of a full block and 198 bytes in 
    //   the last block. It's thus split between them, and we need to be able to recover the full header when the
    //   final block is < PayloadHeader.sizeof. The 2x HMACs are added as well, since they follow the final header...
    usz trailer_size = PayloadHeader.sizeof + ctx.o_hmac_service.iface_hashlen() + ctx.w_hmac_service.iface_hashlen();

    PayloadHeader* tail_hdr = malloc(trailer_size);
    if (null == tail_hdr) return OUT_OF_RESOURCES?;
    defer free(tail_hdr);

    // Enter the loop...
    bool exit_loop = false;
    char[] this_block;   // make accessible in outer scope
    do OUTER: {
        this_block = next_block_callback(stream_block_size);

        if (!this_block.len) {
            if (!block_counter) return PREMATURE_END_OF_STREAM?;

            break OUTER;   // exit the loop immediately on a zero-length block...
        }

        // Should always prep to exit the loop when a full stream block wasn't received.
        exit_loop = this_block.len < stream_block_size;

        if (exit_loop && this_block.len < trailer_size) return PREMATURE_END_OF_STREAM?;

        // consume W-HMAC contents
        ctx.w_hmac_service.iface_update(
            !exit_loop ? this_block : this_block[..^(ctx.w_hmac_service.iface_hashlen() + 1)]
        );

        // Memcpy the trailing information from the block into the shadow buffer.
        if (exit_loop) ((char*)tail_hdr)[:trailer_size] = this_block[^trailer_size..];

        // Roll the CryptoProvider and IV when the blocks counter hits the roll_interval.
        if (0 == (block_counter % in_hdr.roll_interval)) {
            char[] iv_hash = ctx.digest_service.iface_digest(nonce[:iv_size])[:iv_size];
            nonce[:iv_size] = iv_hash[:iv_size];
            free(iv_hash.ptr);

            ctx.crypto_service.iface_init(digested_key, nonce[:iv_size])!;
        } else {
            // XOR the nonce/IV with a 'seed' value based on the block counter.
            char which = in_hdr.nonce_seeds[block_counter % SEEDS_COUNT];

            for (usz i = 0; i < iv_size; ++i) nonce[i] ^= which;

            if (!seed_step_counter) {
                for (usz i = 0; i < iv_size; ++i) nonce[i] ^= in_hdr.nonce_seed_step;
                seed_step_counter = in_hdr.nonce_seed_step;
            }

            --seed_step_counter;
        }

        // Reassign the block to the content WITHOUT the trailing header, if this is the final block.
        this_block = !exit_loop ? this_block : this_block[:(this_block.len - trailer_size)];

        ctx.crypto_service.decrypt_mut(this_block)!;   // decrypt

        if (exit_loop) this_block = ctx.crypto_service.unpad(this_block)!;   // NOTE: this reallocates the pointer!

        ctx.o_hmac_service.iface_update(this_block);   // consume O-HMAC contents

        yield_callback(this_block);   // emit
        bytes_counter += this_block.len;   // measure

        ++block_counter;
    } while (!exit_loop);

    free (this_block.ptr);

    // At this point, the trailing header is awaiting parsing and both HMACs need to be checked.
    if (HEADER_MAGIC != tail_hdr.magic[:HEADER_MAGIC.len]) return STREAM_MISSING_POST_HEADER?;

    char[] final_original_hmac = ctx.o_hmac_service.iface_final();
    char[] retrieved_o_hmac = ((char*)tail_hdr)[PayloadHeader.sizeof : ctx.o_hmac_service.iface_hashlen()];
    defer free(final_original_hmac);

    char[] final_wrapper_hmac = ctx.w_hmac_service.iface_final();
    char[] retrieved_w_hmac = ((char*)tail_hdr)[(PayloadHeader.sizeof + ctx.w_hmac_service.iface_hashlen()) : ctx.w_hmac_service.iface_hashlen()];
    defer free(final_wrapper_hmac);

    // Ensure we got the right HMAC values. These must obviously be exact reconstructions.
    if (final_original_hmac != retrieved_o_hmac) return BAD_ORIGINAL_HMAC?;
    if (final_wrapper_hmac != retrieved_w_hmac) return BAD_WRAPPER_HMAC?;
}
