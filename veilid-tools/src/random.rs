use rand::{Rng, TryCryptoRng, TryRng};

/// Cryptographically secure RNG that draws from the thread-local random source.
///
/// Implements [`TryRng`] and [`TryCryptoRng`]; the `rand_core` blanket impls make it a
/// [`Rng`] and [`CryptoRng`](rand::CryptoRng) wherever a `rand` generator is expected.
#[derive(Clone, Copy, Debug, Default)]
pub struct VeilidRng;

impl TryRng for VeilidRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(get_random_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(get_random_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        random_bytes(dest);
        Ok(())
    }
}

impl TryCryptoRng for VeilidRng {}

/// Fill `dest` with cryptographically secure random bytes.
pub fn random_bytes(dest: &mut [u8]) {
    rand::rng().fill_bytes(dest);
}

/// Return a cryptographically secure random `u32`.
#[must_use]
pub fn get_random_u32() -> u32 {
    rand::rng().next_u32()
}

/// Return a cryptographically secure random `u64`.
#[must_use]
pub fn get_random_u64() -> u64 {
    rand::rng().next_u64()
}
