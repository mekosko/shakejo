extern crate alloc;
use alloc::boxed::Box;

use snow::{
	params::{CipherChoice, DHChoice, HashChoice},
	resolvers::CryptoResolver,
	types as inner,
};

use super::{blake2s::HashBLAKE2s, ciphers::CipherChaChaPoly, dh25519::Dh25519};

#[derive(Clone)]
pub struct FakeRandomNumberGenerator(pub u8);

impl rand_core::RngCore for FakeRandomNumberGenerator {
	fn next_u32(&mut self) -> u32 {
		// Generate and return pseudo random number

		self.0 = self.0.checked_add(1).unwrap();

		self.0 as u32
	}

	fn next_u64(&mut self) -> u64 {
		// Just generate and return u32 number

		self.next_u32() as u64
	}

	fn fill_bytes(&mut self, dest: &mut [u8]) {
		// Fill provided array with pseudo random

		let f = |b: &mut u8| {
			self.0 = self.0.checked_add(1).unwrap();

			*b = self.0
		};
		dest.iter_mut().for_each(f);
	}

	fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
		// Just call already provided method

		self.fill_bytes(dest);

		Ok(())
	}
}

impl rand_core::CryptoRng for FakeRandomNumberGenerator {}

impl inner::Random for FakeRandomNumberGenerator {}

pub struct MyResolver;

impl CryptoResolver for MyResolver {
	fn resolve_rng(&self) -> Option<Box<dyn inner::Random>> {
		Some(Box::new(FakeRandomNumberGenerator(0)))
	}

	fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn inner::Dh>> {
		match *choice {
			DHChoice::Curve25519 => Some(Box::new(Dh25519::default())),
			_ => unreachable!(),
		}
	}

	fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn inner::Hash>> {
		match *choice {
			HashChoice::Blake2s => Some(Box::new(HashBLAKE2s::default())),
			_ => unreachable!(),
		}
	}

	fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn inner::Cipher>> {
		match *choice {
			CipherChoice::ChaChaPoly => Some(Box::new(CipherChaChaPoly::default())),
			_ => unreachable!(),
		}
	}
}
