use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit};
use snow::types as inner;

type Result = core::result::Result<usize, snow::Error>;

#[derive(Default)]
pub struct CipherChaChaPoly {
	inner: Key,
}

fn expand(n: [u8; 8]) -> [u8; 12] {
	let mut nonce = [0u8; 12];

	nonce[4..].copy_from_slice(&n);

	nonce
}

impl inner::Cipher for CipherChaChaPoly {
	fn name(&self) -> &'static str {
		"ChaChaPoly"
	}

	fn set(&mut self, key: &[u8]) {
		self.inner.copy_from_slice(key);
	}

	fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
		let (data, tag_data) = out.split_at_mut(plaintext.len());

		data.copy_from_slice(plaintext);

		let tag = ChaCha20Poly1305::new(&self.inner.into())
			.encrypt_in_place_detached(&expand(nonce.to_le_bytes()).into(), authtext, data)
			.unwrap();

		tag_data[..tag.len()].copy_from_slice(tag.as_slice());

		plaintext.len() + tag.len()
	}

	fn decrypt(&self, nonce: u64, authtext: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result {
		let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - 16);

		let (nonce, data) = (
			&expand(nonce.to_le_bytes()).into(),
			&mut out[..ciphertext.len()],
		);
		data.copy_from_slice(&ciphertext);

		ChaCha20Poly1305::new(&self.inner.into())
			.decrypt_in_place_detached(nonce, authtext, data, tag.into())
			.map_err(|_| snow::Error::Decrypt)?;

		Ok(ciphertext.len())
	}
}
