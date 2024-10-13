use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::ops::Neg;

use super::ciphertext::Ciphertext;

/// A key to encrypt a message. The encryption key is implemented with elliptic curve
/// cryptography, where S is the scalar field and P is the elliptic curve point.
///
/// The encryption key should be created from the secret key [`DecryptKey`].
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct EncryptKey<E: Pairing> {
    /// The group generator.
    pub(crate) generator: E::G1Affine,
    /// The public key.
    pub(crate) y: E::G1Affine, // rG
}

impl<E: Pairing> EncryptKey<E> {
    /// Encrypt a message `m` with randomness `r`. Ciphertext is (rG, m + rY).
    pub fn encrypt(&self, m: E::G1Affine, r: E::ScalarField) -> Ciphertext<E> {
        let a = self.generator * r;
        let b = self.y * r + m;
        Ciphertext(a.into(), b.into())
    }

    /// Rerandomize a ciphertext with randomness `r`. Ciphertext is (a + rG, b + rY).
    pub fn rerandomize(&self, ct: Ciphertext<E>, r: E::ScalarField) -> Ciphertext<E> {
        let a = ct.0 + self.generator * r;
        let b = ct.1 + self.y * r;
        Ciphertext(a.into(), b.into())
    }
}

/// A key to decrypt a message. The decryption key is implemented with elliptic curve
/// cryptography, where S is the scalar field and P is the elliptic curve point.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct DecryptKey<E: Pairing> {
    pub(crate) generator: E::G1Affine,
    pub(crate) secret: E::ScalarField, // x
    pub(crate) encrypt_key: EncryptKey<E>,
}

impl<E: Pairing> DecryptKey<E> {
    /// Create a new decryption key with group generator `generator` and secret `x`.
    pub fn new(generator: E::G1Affine, x: E::ScalarField) -> Self {
        let y = (generator * x).into();
        Self {
            generator,
            secret: x,
            encrypt_key: EncryptKey { generator, y },
        }
    }

    /// Decrypt a ciphertext (a, b) to get b - ax.
    pub fn decrypt(&self, ct: Ciphertext<E>) -> E::G1Affine {
        (ct.1 + ct.0 * self.secret.neg()).into()
    }
}

impl<E: Pairing> Serialize for EncryptKey<E> {
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

impl<'de, E: Pairing> Deserialize<'de> for EncryptKey<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let generator = E::G1Affine::deserialize_compressed(&bytes[..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the generator"))?;
        let generator_size = generator.serialized_size(ark_serialize::Compress::Yes);
        let y = E::G1Affine::deserialize_compressed(&bytes[generator_size..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the public key"))?;
        Ok(EncryptKey { generator, y })
    }
}

impl<E: Pairing> Serialize for DecryptKey<E> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();
        self.generator
            .serialize_compressed(&mut bytes)
            .map_err(|_| serde::ser::Error::custom("Failed to serialize the generator"))?;
        self.secret
            .serialize_compressed(&mut bytes)
            .map_err(|_| serde::ser::Error::custom("Failed to serialize the secret"))?;

        let enc_bytes = bincode::serialize(&self.encrypt_key).map_err(serde::ser::Error::custom)?;

        bytes.extend(enc_bytes);
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, E: Pairing> Deserialize<'de> for DecryptKey<E> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let generator = E::G1Affine::deserialize_compressed(&bytes[..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the generator"))?;
        let generator_size = generator.serialized_size(ark_serialize::Compress::Yes);
        let secret = E::ScalarField::deserialize_compressed(&bytes[generator_size..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the secret"))?;
        let secret_size = secret.serialized_size(ark_serialize::Compress::Yes);
        let enc_key = bincode::deserialize(&bytes[(generator_size + secret_size)..])
            .map_err(serde::de::Error::custom)?;

        Ok(DecryptKey {
            generator,
            secret,
            encrypt_key: enc_key,
        })
    }
}
