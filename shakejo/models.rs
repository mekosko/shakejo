use blake2::{
	digest::{generic_array::GenericArray, OutputSizeUser},
	Blake2s256, Digest,
};
pub type Result<T> = core::result::Result<T, Error>;

pub enum Error {
	ChaCha20Poly1305,
	ExhaustedCounter,
	Input,
}

#[derive(Clone)]
pub struct Hash {
	pub data: GenericArray<u8, <Blake2s256 as OutputSizeUser>::OutputSize>,
}

impl Hash {
	pub fn new(data: impl AsRef<[u8]>) -> Self {
		let mut hash = Blake2s256::new();

		hash.update(data);

		Self {
			data: hash.finalize(),
		}
	}

	pub fn update(&mut self, data: impl AsRef<[u8]>) {
		let mut hash = Blake2s256::new();

		hash.update(self.data);
		hash.update(data);

		self.data = hash.finalize();
	}
}
