use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::ops::Neg;

use super::{ciphertext::Ciphertext, encrypt::EncryptKey};

/// A key to decrypt a message.
///
/// It is implemented by using G1 in an elliptic curve pairing (the trait E) that defines the data
/// types of the group elements and scalar fields.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct DecryptKey<G: CurveGroup> {
    pub(crate) secret: <G as PrimeGroup>::ScalarField, // x
    pub(crate) encrypt_key: EncryptKey<G>,
}

impl<G: CurveGroup> DecryptKey<G> {
    /// Create a new decryption key with group generator `generator` and secret `x`.
    pub fn new(generator: G::Affine, x: <G as PrimeGroup>::ScalarField) -> Self {
        let generator = generator.into_group();
        let y = generator * x;
        Self {
            secret: x,
            encrypt_key: EncryptKey { generator, y },
        }
    }

    /// Decrypt a ciphertext (a, b) to get b - ax.
    pub fn decrypt(&self, ct: Ciphertext<G>) -> G::Affine {
        (ct.1 + ct.0 * self.secret.neg()).into()
    }

    /// Get the encrypt key.
    pub fn encrypt_key(&self) -> &EncryptKey<G> {
        &self.encrypt_key
    }

    /// Get the scalar field secret (x).
    pub fn secret(&self) -> <G as PrimeGroup>::ScalarField {
        self.secret
    }
}

impl<G: CurveGroup> Serialize for DecryptKey<G> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = Vec::new();
        self.secret
            .serialize_compressed(&mut bytes)
            .map_err(|_| serde::ser::Error::custom("Failed to serialize the secret"))?;

        let enc_bytes = bincode::serialize(&self.encrypt_key).map_err(serde::ser::Error::custom)?;

        bytes.extend(enc_bytes);
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, G: CurveGroup> Deserialize<'de> for DecryptKey<G> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        let secret = <G as PrimeGroup>::ScalarField::deserialize_compressed(&bytes[..])
            .map_err(|_| serde::de::Error::custom("Failed to deserialize the secret"))?;
        let secret_size = secret.serialized_size(ark_serialize::Compress::Yes);
        let enc_key =
            bincode::deserialize(&bytes[(secret_size)..]).map_err(serde::de::Error::custom)?;

        Ok(DecryptKey {
            secret,
            encrypt_key: enc_key,
        })
    }
}
