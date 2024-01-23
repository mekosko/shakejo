use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};

use crate::{Error, Result};

const HASH: &[u8] = &[];

struct Key {
	k: chacha20poly1305::Key,
	n: u64,
}

pub struct Transport {
	encrypt: Key,
	decrypt: Key,
}

fn nonce(n: u64) -> Nonce {
	let mut nonce = [0u8; 12];

	nonce[4..].copy_from_slice(&n.to_le_bytes());

	Nonce::from(nonce)
}

impl Transport {
	pub fn new(encrypt: chacha20poly1305::Key, decrypt: chacha20poly1305::Key) -> Self {
		Self {
			encrypt: Key { k: encrypt, n: 0 },
			decrypt: Key { k: decrypt, n: 0 },
		}
	}

	pub fn decrypt(&mut self, data: &mut [u8], tag_data: &[u8]) -> Result<()> {
		let tag = chacha20poly1305::Tag::from_slice(tag_data);

		ChaCha20Poly1305::new(&self.decrypt.k)
			.decrypt_in_place_detached(&nonce(self.decrypt.n), HASH, data, tag)
			.map_err(|_| Error::ChaCha20Poly1305)?;

		self.decrypt.n = self.decrypt.n.checked_add(1).ok_or(Error::ExhaustedCounter)?;

		Ok(())
	}

	pub fn encrypt(&mut self, data: &mut [u8], tag_data: &mut [u8]) -> Result<()> {
		let tag = ChaCha20Poly1305::new(&self.encrypt.k)
			.encrypt_in_place_detached(&nonce(self.encrypt.n), HASH, data)
			.map_err(|_| Error::ChaCha20Poly1305)?;

		tag_data.copy_from_slice(tag.as_slice());

		self.encrypt.n = self.encrypt.n.checked_add(1).ok_or(Error::ExhaustedCounter)?;

		Ok(())
	}
}
