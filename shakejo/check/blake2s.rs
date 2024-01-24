use blake2::Digest;
use snow::types as inner;

#[derive(Default)]
pub struct HashBLAKE2s {
	inner: blake2::Blake2s256,
}

impl inner::Hash for HashBLAKE2s {
	fn name(&self) -> &'static str {
		"BLAKE2s"
	}

	fn block_len(&self) -> usize {
		64
	}

	fn hash_len(&self) -> usize {
		32
	}

	fn reset(&mut self) {
		self.inner = blake2::Blake2s::default();
	}

	fn input(&mut self, data: &[u8]) {
		self.inner.update(data);
	}

	fn result(&mut self, out: &mut [u8]) {
		let s = self.inner.finalize_reset();

		out[..32].copy_from_slice(&s);
	}
}
