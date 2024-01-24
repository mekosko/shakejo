use snow::types as inner;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Default)]
pub struct Dh25519 {
	inner: [u8; 32],
	buf: [u8; 32],
}

fn array_from_slice(slice: &[u8]) -> [u8; 32] {
	let mut array = [0; 32];

	array.copy_from_slice(&slice[..32]);

	array
}

extern crate std;

impl inner::Dh for Dh25519 {
	fn name(&self) -> &'static str {
		"25519"
	}

	fn pub_len(&self) -> usize {
		32
	}

	fn priv_len(&self) -> usize {
		32
	}

	fn set(&mut self, k: &[u8]) {
		let inner = StaticSecret::from(array_from_slice(k));

		(self.inner, self.buf) = (inner.to_bytes(), PublicKey::from(&inner).to_bytes());
	}

	fn generate(&mut self, e: &mut dyn inner::Random) {
		let inner = StaticSecret::random_from_rng(e);

		(self.inner, self.buf) = (inner.to_bytes(), PublicKey::from(&inner).to_bytes());
	}

	fn privkey(&self) -> &[u8] {
		&self.inner
	}

	fn pubkey(&self) -> &[u8] {
		&self.buf
	}

	fn dh(&self, key: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
		let key = PublicKey::from(array_from_slice(key));
		let buf = StaticSecret::from(self.inner).diffie_hellman(&key);

		out[..32].copy_from_slice(buf.as_bytes());

		Ok(())
	}
}
