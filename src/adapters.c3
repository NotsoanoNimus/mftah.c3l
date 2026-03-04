/**
 * @file adapters.c3
 * @brief MFTAH crypto and hashing adapters.
 *
 * @author Zack Puhl <github@xmit.xyz>
 * @date 2026-03-03
 *
 *
 * Copyright (c) 2025-2026 Zack Puhl <github@xmit.xyz> - https://github.com/NotsoanoNimus/mftah.c3l
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
module mftah @private;

import std::crypto, std::hash;

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
	fn char[] iface_kdf(char[], char[], uint);

	fn void iface_init(char[]);
	fn void iface_update(char[]);
	fn char[] iface_final();

	fn usz iface_hashlen();
	fn usz iface_keylen();
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
	fn bool iface_is_block_cipher();
}

// ======================================================================================================
// ChaCha20
typedef ChaCha20 (CryptoProvider) = inline std::crypto::chacha20::ChaCha20;
fn void? ChaCha20.iface_init(&self, char[] key, char[] iv) @dynamic => (void)self.init(key[:chacha20::KEY_SIZE], iv[:chacha20::NONCE_SIZE], 1);
fn char[]? ChaCha20.encrypt_mut(&self, char[] input) @dynamic
{
	self.transform(input);
	return input;
}
fn char[]? ChaCha20.decrypt_mut(&self, char[] input) @dynamic
{
	self.transform(input);
	return input;
}
// ChaCha20 doesn't need padding since it's not a block cipher.
fn char[]? ChaCha20.pad(&self, char[] input) @dynamic => input;
fn char[]? ChaCha20.unpad(&self, char[] input) @dynamic => input;
fn usz ChaCha20.block_size(&self) @dynamic => chacha20::BLOCK_SIZE;
fn usz ChaCha20.iv_size(&self) @dynamic => chacha20::NONCE_SIZE;
fn bool ChaCha20.iface_is_block_cipher(&self) @dynamic => false;

// ======================================================================================================
// AES
typedef AesCtx (CryptoProvider) = inline std::crypto::aes::Aes;
fn void? AesCtx.iface_init(&self, char[] key, char[] iv) @dynamic => (void)self.init(AesType.AES256, key, iv[:aes::BLOCKLEN], CBC);
fn char[]? AesCtx.encrypt_mut(&self, char[] input) @dynamic
{
        self.encrypt_buffer(input, input);
        return input;
}
fn char[]? AesCtx.decrypt_mut(&self, char[] input) @dynamic
{
        self.decrypt_buffer(input, input);
        return input;
}
fn char[]? AesCtx.pad(&self, char[] input) @dynamic => util::@pkcs7(aes::BLOCKLEN, input);
fn char[]? AesCtx.unpad(&self, char[] input) @dynamic => util::@unpkcs7(aes::BLOCKLEN, input);
fn usz AesCtx.block_size(&self) @dynamic => aes::BLOCKLEN;
fn usz AesCtx.iv_size(&self) @dynamic => aes::BLOCKLEN;
fn bool AesCtx.iface_is_block_cipher(&self) @dynamic => true;

// ======================================================================================================
// HMAC
typedef Hmac (HmacDigestProvider) <Alg, HASH_BYTES, BLOCK_BYTES, KEY_BYTES> = inline std::hash::hmac::Hmac{Alg, HASH_BYTES, BLOCK_BYTES};
fn char[] Hmac.iface_digest(&self, char[] key, char[] data) @dynamic
{
        char[] res = allocator::alloc_array(mem, char, HASH_BYTES)[:HASH_BYTES];
        res[:HASH_BYTES] = hmac::hash{Alg, HASH_BYTES, BLOCK_BYTES}(key, data)[:HASH_BYTES];
        return res;
}
fn char[] Hmac.iface_kdf(&self, char[] key, char[] salt, uint iterations) @dynamic
{
        char[] res = allocator::new_array(mem, char, HASH_BYTES)[:HASH_BYTES];
        hmac::pbkdf2{Alg, HASH_BYTES, BLOCK_BYTES}(key, salt, iterations, res);
        return res;
}
fn void Hmac.iface_init(&self, char[] key) @dynamic => self.init(key);
fn void Hmac.iface_update(&self, char[] data) @dynamic => self.update(data);
fn char[] Hmac.iface_final(&self) @dynamic
{
        char[] res = allocator::new_array(mem, char, HASH_BYTES)[:HASH_BYTES];
        res[:HASH_BYTES] = self.final()[:HASH_BYTES];
        return res;
}
fn usz Hmac.iface_hashlen(&self) @dynamic => HASH_BYTES;
fn usz Hmac.iface_keylen(&self) @dynamic => KEY_BYTES;

// ======================================================================================================
// Poly1305
typedef Poly1305 (HmacDigestProvider) = inline std::hash::poly1305::Poly1305;
fn char[] Poly1305.iface_digest(&self, char[] key, char[] data) @dynamic
{
        char[] res = allocator::alloc_array(mem, char, poly1305::TAG_SIZE)[:poly1305::TAG_SIZE];
        res[..] = poly1305::hash(data, key[:poly1305::KEY_SIZE])[:poly1305::TAG_SIZE];
        return res;
}
fn char[] Poly1305.iface_kdf(&self, char[] key, char[] salt, uint iterations) @dynamic
{
        char[] res = allocator::alloc_array(mem, char, poly1305::TAG_SIZE)[:poly1305::TAG_SIZE];
        _poly1305_pbkdf2(key, salt, iterations, res);
        return res;
}
fn void _poly1305_pbkdf2(char[] pw, char[] salt, uint iterations, char[] output) @inline @local
{
	usz l = output.len / poly1305::TAG_SIZE;
	usz r = output.len % poly1305::TAG_SIZE;
	Poly1305 hmac;
	hmac.init(pw[:poly1305::KEY_SIZE]);
	char[] dst_curr = output;
	for (usz i = 1; i <= l; i++)
	{
		char[poly1305::TAG_SIZE] tmp @noinit;
		defer mem::zero_volatile(&tmp);
		Poly1305 b = hmac;
		b.update(salt);
		UIntBE be = { (uint)i };
		b.update(&&bitcast(be, char[4]));
		tmp = b.final();
		dst_curr[:poly1305::TAG_SIZE] = tmp[..];
		for (int it = 1; it < iterations; it++)
		{
			b = hmac;
			b.update(&tmp);
			tmp = b.final();
			foreach (x, v : tmp) tmp[x] ^= v;
		}
		dst_curr = dst_curr[poly1305::TAG_SIZE..];
	}
	if (r > 0)
	{
		char[poly1305::TAG_SIZE] out;
		// @derive(&hmac, salt, iterations, l + 1, &tmp);
		char[poly1305::TAG_SIZE] tmp @noinit;
		defer mem::zero_volatile(&tmp);
		Poly1305 b = hmac;
		b.update(salt);
		UIntBE be = { (uint)(l + 1) };
		b.update(&&bitcast(be, char[4]));
		tmp = b.final();
		out[..] = tmp[..];
		for (int it = 1; it < iterations; it++)
		{
			b = hmac;
			b.update(&tmp);
			tmp = b.final();
			foreach (x, v : tmp) out[x] ^= v;
		}
		dst_curr[..] = out[:dst_curr.len];
		mem::zero_volatile(&out);
	}
}
fn void Poly1305.iface_init(&self, char[] key) @dynamic => self.init(key[:poly1305::KEY_SIZE]);
fn void Poly1305.iface_update(&self, char[] data) @dynamic => self.update(data);
fn char[] Poly1305.iface_final(&self) @dynamic
{
        char[] res = allocator::alloc_array(mem, char, poly1305::TAG_SIZE)[:poly1305::TAG_SIZE];
        res[..] = self.final()[:poly1305::TAG_SIZE];
        return res;
}
fn usz Poly1305.iface_hashlen(&self) @dynamic => poly1305::TAG_SIZE;
fn usz Poly1305.iface_keylen(&self) @dynamic => poly1305::KEY_SIZE;

// ======================================================================================================
// Sha256
typedef Sha256 (DigestProvider) = inline std::hash::sha256::Sha256;
typedef HmacSha256 = inline mftah::Hmac{Sha256, sha256::HASH_SIZE, sha256::BLOCK_SIZE, 0};
fn usz Sha256.iface_hashlen(&self) @dynamic => sha256::HASH_SIZE;
fn void Sha256.iface_init(&self) @dynamic => self.init();
fn void Sha256.iface_update(&self, char[] data) @dynamic => self.update(data);
fn char* Sha256.iface_final(&self) @dynamic
{
    char[] ret = allocator::alloc_array(mem, char, sha256::HASH_SIZE)[:sha256::HASH_SIZE];
    ret[..] = self.final()[..];
    return ret;
}
fn char* Sha256.iface_digest(&self, char[] data) @dynamic
{
    char[] ret = allocator::alloc_array(mem, char, sha256::HASH_SIZE)[:sha256::HASH_SIZE];
    ret[..] = sha256::hash(data)[..];
    return ret;
}

// ======================================================================================================
// Sha512
typedef Sha512 (DigestProvider) = inline std::hash::sha512::Sha512;
typedef HmacSha512 = inline mftah::Hmac{Sha512, sha512::HASH_SIZE, sha512::BLOCK_SIZE, 0};
fn usz Sha512.iface_hashlen(&self) @dynamic => sha512::HASH_SIZE;
fn void Sha512.iface_init(&self) @dynamic => self.init();
fn void Sha512.iface_update(&self, char[] data) @dynamic => self.update(data);
fn char* Sha512.iface_final(&self) @dynamic
{
    char[] ret = allocator::alloc_array(mem, char, sha512::HASH_SIZE)[:sha512::HASH_SIZE];
    ret[..] = self.final()[..];
    return ret;
}
fn char* Sha512.iface_digest(&self, char[] data) @dynamic
{
    char[] ret = allocator::alloc_array(mem, char, sha512::HASH_SIZE)[:sha512::HASH_SIZE];
    ret[..] = sha512::hash(data)[..];
    return ret;
}
