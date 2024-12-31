use std::ops::Add;

use ark_ec::CurveGroup;
use serde::{Deserialize, Serialize};

/// A ciphertext is a pair of two points.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
// (rG, m + rY)
pub struct Ciphertext<G: CurveGroup>(pub G, pub G);

// Implement homomorphic addition for Ciphertext

impl<G: CurveGroup> Add for Ciphertext<G> {
    type Output = Ciphertext<G>;

    fn add(self, rhs: Self) -> Self {
        Ciphertext(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<G: CurveGroup> Add for &Ciphertext<G> {
    type Output = Ciphertext<G>;

    fn add(self, rhs: Self) -> Self::Output {
        Ciphertext(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<G: CurveGroup> Add<&Ciphertext<G>> for Ciphertext<G> {
    type Output = Ciphertext<G>;

    fn add(self, rhs: &Self) -> Self::Output {
        Ciphertext(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<G: CurveGroup> Add<Ciphertext<G>> for &Ciphertext<G> {
    type Output = Ciphertext<G>;

    fn add(self, rhs: Ciphertext<G>) -> Self::Output {
        Ciphertext(self.0 + rhs.0, self.1 + rhs.1)
    }
}

// Implement serialization and deserialization for Ciphertext

impl<G: CurveGroup> Serialize for Ciphertext<G> {
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

impl<'de, G: CurveGroup> Deserialize<'de> for Ciphertext<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;

        let a = G::deserialize_compressed(&bytes[..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the first point"))?;

        let a_size = a.serialized_size(ark_serialize::Compress::Yes);
        let b = G::deserialize_compressed(&bytes[a_size..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the second point"))?;

        Ok(Ciphertext(a, b))
    }
}
