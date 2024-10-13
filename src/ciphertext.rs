use std::ops::Add;

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

/// A ciphertext is a pair of two points.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
// (rG, m + rY)
pub struct Ciphertext<E: Pairing>(pub E::G1Affine, pub E::G1Affine);

// Implement homomorphic addition for Ciphertext

impl<E: Pairing> Add for Ciphertext<E> {
    type Output = Ciphertext<E>;

    fn add(self, rhs: Self) -> Self {
        Ciphertext((self.0 + rhs.0).into(), (self.1 + rhs.1).into())
    }
}

impl<E: Pairing> Add for &Ciphertext<E> {
    type Output = Ciphertext<E>;

    fn add(self, rhs: Self) -> Self::Output {
        Ciphertext((self.0 + rhs.0).into(), (self.1 + rhs.1).into())
    }
}

impl<E: Pairing> Add<&Ciphertext<E>> for Ciphertext<E> {
    type Output = Ciphertext<E>;

    fn add(self, rhs: &Self) -> Self::Output {
        Ciphertext((self.0 + rhs.0).into(), (self.1 + rhs.1).into())
    }
}

impl<E: Pairing> Add<Ciphertext<E>> for &Ciphertext<E> {
    type Output = Ciphertext<E>;

    fn add(self, rhs: Ciphertext<E>) -> Self::Output {
        Ciphertext((self.0 + rhs.0).into(), (self.1 + rhs.1).into())
    }
}

// Implement serialization and deserialization for Ciphertext

impl<E: Pairing> Serialize for Ciphertext<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(|_| serde::ser::Error::custom("Failed to serialize the first point"))?;
        self.1
            .serialize_compressed(&mut bytes)
            .map_err(|_| serde::ser::Error::custom("Failed to serialize the second point"))?;

        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, E: Pairing> Deserialize<'de> for Ciphertext<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;

        let a = E::G1Affine::deserialize_compressed(&bytes[..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the first point"))?;

        let a_size = a.serialized_size(ark_serialize::Compress::Yes);
        let b = E::G1Affine::deserialize_compressed(&bytes[a_size..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the second point"))?;

        Ok(Ciphertext(a, b))
    }
}
