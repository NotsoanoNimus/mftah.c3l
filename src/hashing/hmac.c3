// Taken from the C3 stdlib: https://github.com/c3lang/c3c - commit hash 92d56b7a354855da416bf7e863e2e1bed5fcabf0.
//
// ========================================================================================================
// THIS SOURCE CODE HAS BEEN SLIGHTLY MODIFIED FROM ITS ORIGINAL STATE FOR COMPATIBILITY WITH THIS PROJECT.
// ========================================================================================================
module mftah::hashing::hmac{HashAlg, HASH_BYTES, BLOCK_BYTES};


struct Hmac (HmacDigestProvider)
{
	HashAlg a, b;
}

const IPAD @private = 0x36;
const OPAD @private = 0x5C;


fn char[] Hmac.iface_digest(&self, char[] key, char[] data) @dynamic
{
	char[] res = malloc(HASH_BYTES)[:HASH_BYTES];
	res[:HASH_BYTES] = hash(key, data)[:HASH_BYTES];
	return res;
}

fn void Hmac.iface_init(&self, char[] key) @dynamic => self.init(key);
fn void Hmac.iface_update(&self, char[] data) @dynamic => self.update(data);

fn char[] Hmac.iface_final(&self) @dynamic
{
	char[] res = malloc(HASH_BYTES)[:HASH_BYTES];
	res[:HASH_BYTES] = self.final()[:HASH_BYTES];
	return res;
}

fn usz Hmac.iface_hashlen(&self) @dynamic => HASH_BYTES;


fn char[HASH_BYTES] hash(char[] key, char[] message)
{
	Hmac hmac @noinit;
	hmac.init(key);
	hmac.update(message);
	return hmac.final();
}


fn void Hmac.init(&self, char[] key)
{
	char[BLOCK_BYTES] buffer;
	if (key.len > BLOCK_BYTES)
	{
		self.a.init();
		self.a.update(key);
		buffer[:HASH_BYTES] = self.a.final()[..];
	}
	else
	{
		buffer[:key.len] = key[..];
	}

	foreach (&b : buffer) *b ^= IPAD;

	self.a.init();
	self.a.update(&buffer);

	foreach (&b : buffer) *b ^= IPAD ^ OPAD;

	self.b.init();
	self.b.update(&buffer);

	mem::zero_volatile(&buffer);
}

fn void Hmac.update(&self, char[] data)
{
	self.a.update(data);
}

fn char[HASH_BYTES] Hmac.final(&self)
{
	self.b.update(&&self.a.final());
	return self.b.final();
}
