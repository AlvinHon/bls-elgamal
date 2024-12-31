use ark_ec::{CurveGroup, PrimeGroup};
use serde::{Deserialize, Serialize};

use super::ciphertext::Ciphertext;

/// A key to encrypt a message.
///
/// It is implemented by using G1 in an elliptic curve pairing (the trait E) that defines the data
/// types of the group elements and scalar fields.
///
/// The encryption key should be created from the secret key [`DecryptKey`](crate::decrypt::DecryptKey).
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct EncryptKey<G: CurveGroup> {
    /// The group generator.
    pub(crate) generator: G,
    /// The public key.
    pub(crate) y: G, // xG
}

impl<G: CurveGroup> EncryptKey<G> {
    /// Encrypt a message `m` with randomness `r`. Ciphertext is (rG, m + rY).
    pub fn encrypt(&self, m: G::Affine, r: <G as PrimeGroup>::ScalarField) -> Ciphertext<G> {
        let a = self.generator * r;
        let b = self.y * r + m;
        Ciphertext(a, b)
    }

    /// Rerandomize a ciphertext with randomness `r`. Ciphertext is (a + rG, b + rY).
    pub fn rerandomize(
        &self,
        ct: Ciphertext<G>,
        r: <G as PrimeGroup>::ScalarField,
    ) -> Ciphertext<G> {
        let a = ct.0 + self.generator * r;
        let b = ct.1 + self.y * r;
        Ciphertext(a, b)
    }

    /// Get the generator.
    pub fn generator(&self) -> G::Affine {
        self.generator.into_affine()
    }

    /// Get the component Y (= xG) where x is the secret key.
    pub fn y(&self) -> G::Affine {
        self.y.into_affine()
    }
}

impl<G: CurveGroup> Serialize for EncryptKey<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();
        self.generator
            .serialize_compressed(&mut bytes)
            .map_err(|_| serde::ser::Error::custom("Failed to serialize the generator"))?;
        self.y
            .serialize_compressed(&mut bytes)
            .map_err(|_| serde::ser::Error::custom("Failed to serialize the public key"))?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, G: CurveGroup> Deserialize<'de> for EncryptKey<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let generator = G::deserialize_compressed(&bytes[..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the generator"))?;
        let generator_size = generator.serialized_size(ark_serialize::Compress::Yes);
        let y = G::deserialize_compressed(&bytes[generator_size..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the public key"))?;
        Ok(EncryptKey { generator, y })
    }
}
