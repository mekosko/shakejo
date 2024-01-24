use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{models as inner, Error, Result, Transport};

pub const NOISE: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

pub(crate) const MESSAGE_A_LEN: usize = 32 + 32 + 16 + 16;
pub(crate) const MESSAGE_B_LEN: usize = 32 + 16;

pub struct State(PublicKey, PublicKey);

pub struct Shake<T>
where
	T: RngCore + CryptoRng + Clone,
{
	ns: StaticSecret,

	hash: inner::Hash,
	ck: inner::Hash,

	k: chacha20poly1305::Key,
	n: u64,

	random: T,
}

fn array_from_slice(slice: &[u8]) -> [u8; 32] {
	let mut array = [0; 32];

	array.copy_from_slice(&slice[..32]);

	array
}

impl<T> Shake<T>
where
	T: RngCore + CryptoRng + Clone,
{
	pub fn new(ns: StaticSecret, random: T) -> Self {
		let mut hash = inner::Hash::new(NOISE);

		let ck = hash.clone();

		hash.update([]);

		Self {
			ns,

			hash,
			ck,

			k: chacha20poly1305::Key::default(),
			n: 0,

			random,
		}
	}

	fn mix_key(&mut self, data: &[u8]) -> Result<()> {
		let ck = self.ck.data.as_slice();

		// SPEC: `with the chaining_key as HKDF salt`
		let hkdf = hkdf::SimpleHkdf::<blake2::Blake2s256>::new(Some(ck), data);

		let mut data = [0u8; 64];

		// Length of data equals 64 so always okay
		hkdf.expand(&[], data.as_mut_slice()).unwrap();

		self.ck.data.as_mut_slice().copy_from_slice(&data[..32]);
		self.k.as_mut_slice().copy_from_slice(&data[32..]);

		self.n = 0;

		Ok(())
	}

	fn nonce(&self) -> Nonce {
		let mut nonce = [0u8; 12];

		nonce[4..].copy_from_slice(&self.n.to_le_bytes());

		Nonce::from(nonce)
	}

	pub fn decrypt(&mut self, m: &mut [u8]) -> Result<()> {
		// We need to hash ciphertext, but we also need previous hash
		let previous_hash = self.hash.clone();

		self.hash.update(&m);

		// Buffer with ciphertext for plaintext
		let (data, tag_data) = m.split_at_mut(m.len() - 16);

		let tag = chacha20poly1305::Tag::from_slice(tag_data);

		ChaCha20Poly1305::new(&self.k)
			.decrypt_in_place_detached(&self.nonce(), previous_hash.data.as_slice(), data, tag)
			.map_err(|_| Error::ChaCha20Poly1305)?;

		self.n = self.n.checked_add(1).ok_or(Error::ExhaustedCounter)?;

		Ok(())
	}

	pub fn encrypt(&mut self, m: &mut [u8]) -> Result<()> {
		// Buffer with plaintext for ciphertext
		let (data, tag_data) = m.split_at_mut(m.len() - 16);

		let tag = ChaCha20Poly1305::new(&self.k)
			.encrypt_in_place_detached(&self.nonce(), self.hash.data.as_slice(), data)
			.map_err(|_| Error::ChaCha20Poly1305)?;

		tag_data.copy_from_slice(tag.as_slice());

		// We need to hash ciphertext
		self.hash.update(m);

		self.n = self.n.checked_add(1).ok_or(Error::ExhaustedCounter)?;

		Ok(())
	}

	pub fn transport(self) -> Result<(chacha20poly1305::Key, chacha20poly1305::Key)> {
		let ck = self.ck.data.as_slice();

		// SPEC: `with the chaining_key as HKDF salt`
		let hkdf = hkdf::SimpleHkdf::<blake2::Blake2s256>::new(Some(ck), &[]);

		let mut data = [0u8; 64];

		// Length of data equals 64 so always okay
		hkdf.expand(&[], data.as_mut_slice()).unwrap();

		Ok((
			Key::clone_from_slice(&data[..32]),
			Key::clone_from_slice(&data[32..]),
		))
	}

	pub fn make_message_aa(&mut self, m: &mut [u8], rs: PublicKey) -> Result<StaticSecret> {
		if m.len() < 32 {
			return Err(Error::Input);
		}
		let ephemeral = StaticSecret::random_from_rng(self.random.clone());

		self.hash.update(rs.as_bytes());

		// -> e
		let ne = m.split_at_mut(32).0;

		ne.copy_from_slice(PublicKey::from(&ephemeral).as_bytes());

		self.hash.update(ne);

		// -> e, es
		let shared = ephemeral.diffie_hellman(&rs);

		self.mix_key(shared.as_bytes())?;

		//
		Ok(ephemeral)
	}

	pub fn make_message_ab(&mut self, m: &mut [u8], rs: PublicKey) -> Result<()> {
		if m.len() < 48 {
			return Err(Error::Input);
		}

		// -> e, es, s
		let ns = m.split_at_mut(48).0;

		ns[..32].copy_from_slice(PublicKey::from(&self.ns).as_bytes());

		self.encrypt(ns)?;

		// -> e, es, s, ss
		let shared = self.ns.diffie_hellman(&rs);

		self.mix_key(shared.as_bytes())?;

		Ok(())
	}

	pub fn make_message_a(&mut self, m: &mut [u8], rs: PublicKey) -> Result<StaticSecret> {
		if m.len() < MESSAGE_A_LEN {
			return Err(Error::Input);
		}

		// -> e, es
		let (aa, m) = m.split_at_mut(32);

		let ephemeral = self.make_message_aa(aa, rs)?;

		// -> e, es, s, ss
		let (ab, m) = m.split_at_mut(48);

		self.make_message_ab(ab, rs)?;

		// payload
		self.encrypt(m)?;

		Ok(ephemeral)
	}

	pub fn read_message_aa(&mut self, m: &mut [u8]) -> Result<PublicKey> {
		if m.len() < 32 {
			return Err(Error::Input);
		}
		self.hash.update(PublicKey::from(&self.ns).as_bytes());

		// <- e
		let re = m.split_at_mut(32).0;

		let remote_ephemeral = PublicKey::from(array_from_slice(re));

		self.hash.update(remote_ephemeral.as_bytes());

		// <- e, se
		let shared = self.ns.diffie_hellman(&remote_ephemeral);

		self.mix_key(shared.as_bytes())?;

		Ok(remote_ephemeral)
	}

	pub fn read_message_ab(&mut self, m: &mut [u8]) -> Result<PublicKey> {
		if m.len() < 48 {
			return Err(Error::Input);
		}

		// <- e, se, s
		let rs = m.split_at_mut(48).0;

		self.decrypt(rs)?;

		let remote_static = PublicKey::from(array_from_slice(rs));

		// <- e, se, s, ss
		let shared = self.ns.diffie_hellman(&remote_static);

		self.mix_key(shared.as_bytes())?;

		Ok(remote_static)
	}

	pub fn read_message_a(&mut self, m: &mut [u8]) -> Result<State> {
		if m.len() < MESSAGE_A_LEN {
			return Err(Error::Input);
		}

		// <- e, se
		let (aa, m) = m.split_at_mut(32);

		let remote_ephemeral = self.read_message_aa(aa)?;

		// <- e, se, s, ss
		let (ab, m) = m.split_at_mut(48);

		let remote_static = self.read_message_ab(ab)?;

		// payload
		self.decrypt(m)?;

		Ok(State(remote_ephemeral, remote_static))
	}

	pub fn make_message_ba(&mut self, m: &mut [u8], re: PublicKey, rs: PublicKey) -> Result<()> {
		if m.len() < 32 {
			return Err(Error::Input);
		}
		let ephemeral = StaticSecret::random_from_rng(self.random.clone());

		// -> e
		let ne = m.split_at_mut(32).0;

		ne.copy_from_slice(PublicKey::from(&ephemeral).as_bytes());

		self.hash.update(ne);

		// -> e, ee
		let shared = ephemeral.diffie_hellman(&re);

		self.mix_key(shared.as_bytes())?;

		// -> e, ee, es
		let shared = ephemeral.diffie_hellman(&rs);

		self.mix_key(shared.as_bytes())?;

		Ok(())
	}

	pub fn make_message_b(mut self, m: &mut [u8], state: State) -> Result<Transport> {
		if m.len() < MESSAGE_B_LEN {
			return Err(Error::Input);
		}

		// -> e, ee, es
		let (ba, m) = m.split_at_mut(32);

		self.make_message_ba(ba, state.0, state.1)?;

		// payload
		self.encrypt(m)?;

		// new responder
		let (decrypt, encrypt) = self.transport()?;

		Ok(Transport::new(encrypt, decrypt))
	}

	pub fn read_message_ba(&mut self, m: &mut [u8], ne: StaticSecret) -> Result<()> {
		if m.len() < 32 {
			return Err(Error::Input);
		}

		// <- e
		let re = m.split_at_mut(32).0;

		let remote_ephemeral = PublicKey::from(array_from_slice(re));

		self.hash.update(re);

		// <- e, ee
		let shared = ne.diffie_hellman(&remote_ephemeral);

		self.mix_key(shared.as_bytes())?;

		// <- e, ee, se
		let shared = self.ns.diffie_hellman(&remote_ephemeral);

		self.mix_key(shared.as_bytes())?;

		Ok(())
	}

	pub fn read_message_b(mut self, m: &mut [u8], ne: StaticSecret) -> Result<Transport> {
		if m.len() < MESSAGE_B_LEN {
			return Err(Error::Input);
		}

		// <- e, ee, se
		let (ba, m) = m.split_at_mut(32);

		self.read_message_ba(ba, ne)?;

		// payload
		self.decrypt(m)?;

		// new requester
		let (encrypt, decrypt) = self.transport()?;

		Ok(Transport::new(encrypt, decrypt))
	}
}
