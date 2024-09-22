use std::ops::{Add, Mul, Sub};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use super::ciphertext::Ciphertext;

/// A key to encrypt a message. The encryption key is implemented with elliptic curve
/// cryptography, where S is the scalar field and P is the elliptic curve point.
///
/// The encryption key should be created from the secret key [`DecryptKey`].
#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) struct EncryptKey<S, P>
where
    S: CanonicalSerialize + CanonicalDeserialize,
    P: Copy + Clone + Add<Output = P> + CanonicalSerialize + CanonicalDeserialize,
    for<'a> P: Mul<&'a S, Output = P>,
{
    /// The group generator.
    pub(crate) generator: P,
    /// The public key.
    pub(crate) y: P, // rG

    pub(crate) phantom: core::marker::PhantomData<S>,
}

impl<S, P> EncryptKey<S, P>
where
    S: CanonicalSerialize + CanonicalDeserialize,
    P: Copy + Clone + Add<Output = P> + CanonicalSerialize + CanonicalDeserialize,
    for<'a> P: Mul<&'a S, Output = P>,
{
    /// Encrypt a message `m` with randomness `r`. Ciphertext is (rG, m + rY).
    pub fn encrypt(&self, m: P, r: S) -> Ciphertext<P> {
        let a = self.generator * &r;
        let b = self.y * &r + m;
        Ciphertext(a, b)
    }
}

/// A key to decrypt a message. The decryption key is implemented with elliptic curve
/// cryptography, where S is the scalar field and P is the elliptic curve point.
#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) struct DecryptKey<S, P>
where
    S: CanonicalSerialize + CanonicalDeserialize,
    P: Copy
        + Clone
        + Add<Output = P>
        + Mul<S, Output = P>
        + Sub<Output = P>
        + CanonicalSerialize
        + CanonicalDeserialize,
    for<'a> P: Mul<&'a S, Output = P>,
{
    pub(crate) generator: P,
    pub(crate) secret: S, // x
    pub(crate) encrypt_key: EncryptKey<S, P>,
}

impl<S, P> DecryptKey<S, P>
where
    S: CanonicalSerialize + CanonicalDeserialize,
    P: Copy
        + Clone
        + Add<Output = P>
        + Mul<S, Output = P>
        + Sub<Output = P>
        + CanonicalSerialize
        + CanonicalDeserialize,
    for<'a> P: Mul<&'a S, Output = P>,
{
    /// Create a new decryption key with group generator `generator` and secret `x`.
    pub fn new(generator: P, x: S) -> Self {
        let y = generator * &x;
        Self {
            generator,
            secret: x,
            encrypt_key: EncryptKey {
                generator,
                y,
                phantom: core::marker::PhantomData,
            },
        }
    }

    /// Decrypt a ciphertext (a, b) to get b - ax.
    pub fn decrypt(&self, ct: Ciphertext<P>) -> P {
        ct.1 - ct.0 * &self.secret
    }
}

impl<S, P> Serialize for EncryptKey<S, P>
where
    S: CanonicalSerialize + CanonicalDeserialize,
    P: Copy + Clone + Add<Output = P> + CanonicalSerialize + CanonicalDeserialize,
    for<'a> P: Mul<&'a S, Output = P>,
{
    fn serialize<E>(&self, serializer: E) -> Result<E::Ok, E::Error>
    where
        E: serde::Serializer,
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

impl<'de, S, P> Deserialize<'de> for EncryptKey<S, P>
where
    S: CanonicalSerialize + CanonicalDeserialize,
    P: Copy + Clone + Add<Output = P> + CanonicalSerialize + CanonicalDeserialize,
    for<'a> P: Mul<&'a S, Output = P>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let generator = P::deserialize_compressed(&bytes[..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the generator"))?;
        let generator_size = generator.serialized_size(ark_serialize::Compress::Yes);
        let y = P::deserialize_compressed(&bytes[generator_size..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the public key"))?;
        Ok(EncryptKey {
            generator,
            y,
            phantom: core::marker::PhantomData,
        })
    }
}

impl<S, P> Serialize for DecryptKey<S, P>
where
    S: CanonicalSerialize + CanonicalDeserialize,
    P: Copy
        + Clone
        + Add<Output = P>
        + Mul<S, Output = P>
        + Sub<Output = P>
        + CanonicalSerialize
        + CanonicalDeserialize,
    for<'a> P: Mul<&'a S, Output = P>,
{
    fn serialize<E>(&self, serializer: E) -> Result<E::Ok, E::Error>
    where
        E: serde::Serializer,
    {
        let mut bytes = Vec::new();
        self.generator
            .serialize_compressed(&mut bytes)
            .map_err(|_| serde::ser::Error::custom("Failed to serialize the generator"))?;
        self.secret
            .serialize_compressed(&mut bytes)
            .map_err(|_| serde::ser::Error::custom("Failed to serialize the secret"))?;

        let enc_bytes =
            bincode::serialize(&self.encrypt_key).map_err(|e| serde::ser::Error::custom(e))?;

        bytes.extend(enc_bytes);
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, S, P> Deserialize<'de> for DecryptKey<S, P>
where
    S: CanonicalSerialize + CanonicalDeserialize,
    P: Copy
        + Clone
        + Add<Output = P>
        + Mul<S, Output = P>
        + Sub<Output = P>
        + CanonicalSerialize
        + CanonicalDeserialize,
    for<'a> P: Mul<&'a S, Output = P>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let generator = P::deserialize_compressed(&bytes[..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the generator"))?;
        let generator_size = generator.serialized_size(ark_serialize::Compress::Yes);
        let secret = S::deserialize_compressed(&bytes[generator_size..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the secret"))?;
        let secret_size = secret.serialized_size(ark_serialize::Compress::Yes);
        let enc_key: EncryptKey<S, P> =
            bincode::deserialize(&bytes[(generator_size + secret_size)..])
                .map_err(|e| serde::de::Error::custom(e))?;

        Ok(DecryptKey {
            generator,
            secret,
            encrypt_key: enc_key,
        })
    }
}
