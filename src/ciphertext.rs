use std::ops::Add;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

/// A ciphertext is a pair of two points.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
// (rG, m + rY)
pub struct Ciphertext<P>(pub P, pub P);

// Implement homomorphic addition for Ciphertext

impl<P> Add for Ciphertext<P>
where
    P: Add<Output = P>,
{
    type Output = Ciphertext<P>;

    fn add(self, rhs: Self) -> Self {
        Ciphertext(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<P> Add for &Ciphertext<P>
where
    for<'a> &'a P: Add<&'a P, Output = P>,
{
    type Output = Ciphertext<P>;

    fn add(self, rhs: Self) -> Self::Output {
        Ciphertext(&self.0 + &rhs.0, &self.1 + &rhs.1)
    }
}

impl<P> Add<&Ciphertext<P>> for Ciphertext<P>
where
    for<'a> P: Add<&'a P, Output = P>,
{
    type Output = Ciphertext<P>;

    fn add(self, rhs: &Self) -> Self::Output {
        Ciphertext(self.0 + &rhs.0, self.1 + &rhs.1)
    }
}

impl<P> Add<Ciphertext<P>> for &Ciphertext<P>
where
    for<'a> &'a P: Add<P, Output = P>,
{
    type Output = Ciphertext<P>;

    fn add(self, rhs: Ciphertext<P>) -> Self::Output {
        Ciphertext(&self.0 + rhs.0, &self.1 + rhs.1)
    }
}

// Implement serialization and deserialization for Ciphertext

impl<P> Serialize for Ciphertext<P>
where
    P: CanonicalSerialize + CanonicalDeserialize,
{
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

impl<'de, P> Deserialize<'de> for Ciphertext<P>
where
    P: CanonicalSerialize + CanonicalDeserialize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;

        let a = P::deserialize_compressed(&bytes[..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the first point"))?;

        let a_size = a.serialized_size(ark_serialize::Compress::Yes);
        let b = P::deserialize_compressed(&bytes[a_size..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the second point"))?;

        Ok(Ciphertext(a, b))
    }
}
