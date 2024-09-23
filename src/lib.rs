//! # Elgamal Encryption
//!
//! This crate provides an implementation of the Elgamal encryption scheme over elliptic curves using the BLS12-381 curve (G1).
//!
//! ## Example
//!
//! ```rust
//! use ark_std::UniformRand;
//! use bls_elgamal::{Fr, SecretKey, G1};
//! use rand::prelude::StdRng;
//! use rand_core::SeedableRng;
//!     
//! let mut rng = StdRng::from_entropy();
//! let x = Fr::rand(&mut rng);
//! let g1: G1 = G1::rand(&mut rng);
//!     
//! // Create a secret key and a public key
//! let sk = SecretKey::new(g1, x);
//! let pk = sk.public_key();
//!
//! // Define a message and randomness
//! let m = G1::rand(&mut rng);
//! let r = Fr::rand(&mut rng);
//!
//! // Encrypt and decrypt the message
//! let ciphertext = pk.encrypt(m, r);
//! let decrypted_m = sk.decrypt(ciphertext);
//!
//! assert_eq!(m, decrypted_m);
//! ```

pub(crate) mod algorithm;
pub(crate) mod ciphertext;
pub use ciphertext::Ciphertext;

use ark_bls12_381::{Bls12_381 as F, G1Projective};
use ark_ec::pairing::Pairing;
use serde::{Deserialize, Serialize};

// re-export the curve types
pub type G1 = G1Projective;
pub type Fr = <F as Pairing>::ScalarField;

/// A secret key for Elgamal encryption. The secret key is used to decrypt messages.
#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretKey {
    inner: algorithm::DecryptKey<Fr, G1>,
}

impl SecretKey {
    /// Create a new secret key with group generator `g1` and secret `x`.
    pub fn new(g1: G1, x: Fr) -> Self {
        Self {
            inner: algorithm::DecryptKey::new(g1, x),
        }
    }

    /// Decrypt a ciphertext `ct` to get the message.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ark_std::UniformRand;
    /// use bls_elgamal::{Fr, SecretKey, G1};
    /// use rand::prelude::StdRng;
    /// use rand_core::SeedableRng;
    ///
    /// let mut rng = StdRng::from_entropy();
    /// let x = Fr::rand(&mut rng);
    /// let g1: G1 = G1::rand(&mut rng);
    /// let m = G1::rand(&mut rng);
    ///     
    /// let sk = SecretKey::new(g1, x);
    /// let pk = sk.public_key();
    ///
    /// let r = Fr::rand(&mut rng);
    /// let ct = pk.encrypt(m, r);
    /// let d_m = sk.decrypt(ct);
    ///
    /// assert_eq!(m, d_m);
    /// ```
    pub fn decrypt(&self, ct: Ciphertext<G1>) -> G1 {
        self.inner.decrypt(ct)
    }

    /// Get the public key from the secret key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.encrypt_key,
        }
    }
}

/// A public key for Elgamal encryption. The public key is used to encrypt messages.
///
/// The public key is created from the secret key [`SecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    inner: algorithm::EncryptKey<Fr, G1>,
}

impl PublicKey {
    /// Encrypt a message `m` with randomness `r` to get a ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ark_std::UniformRand;
    /// use bls_elgamal::{Fr, SecretKey, G1};
    /// use rand::prelude::StdRng;
    /// use rand_core::SeedableRng;
    ///
    /// let mut rng = StdRng::from_entropy();
    /// let x = Fr::rand(&mut rng);
    /// let g1: G1 = G1::rand(&mut rng);
    ///
    /// let sk = SecretKey::new(g1, x);
    /// let pk = sk.public_key();
    ///
    /// let m = G1::rand(&mut rng);
    /// let r = Fr::rand(&mut rng);
    ///
    /// let ct = pk.encrypt(m, r);
    /// ```
    pub fn encrypt(&self, m: G1, r: Fr) -> Ciphertext<G1> {
        self.inner.encrypt(m, r)
    }

    /// Rerandomize a ciphertext `ct` with randomness `r`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ark_std::UniformRand;
    /// use bls_elgamal::{Fr, SecretKey, G1};
    /// use rand::prelude::StdRng;
    /// use rand_core::SeedableRng;
    ///
    /// let mut rng = StdRng::from_entropy();
    /// let x = Fr::rand(&mut rng);
    /// let g1: G1 = G1::rand(&mut rng);
    ///
    /// let sk = SecretKey::new(g1, x);
    /// let pk = sk.public_key();
    ///
    /// let m = G1::rand(&mut rng);
    /// let r = Fr::rand(&mut rng);
    ///
    /// let ct = pk.encrypt(m, r);
    /// let new_ct = pk.rerandomize(ct, Fr::rand(&mut rng));
    ///
    /// assert_ne!(ct, new_ct);
    ///
    /// let d_m = sk.decrypt(new_ct);
    /// assert_eq!(m, d_m);
    /// ```
    pub fn rerandomize(&self, ct: Ciphertext<G1>, r: Fr) -> Ciphertext<G1> {
        self.inner.rerandomize(ct, r)
    }
}
