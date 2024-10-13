#![doc = include_str!("../README.md")]

pub mod ciphertext;
pub use ciphertext::Ciphertext;

pub mod decrypt;
pub use decrypt::DecryptKey;

pub mod encrypt;
pub use encrypt::EncryptKey;

use ark_ec::{pairing::Pairing, CurveGroup, Group};
use serde::{Deserialize, Serialize};

// re-export the curve types
pub type G1 = <ark_bls12_381::Bls12_381 as Pairing>::G1;
pub type G1Affine = <G1 as CurveGroup>::Affine;
pub type Fr = <G1 as Group>::ScalarField;

/// A secret key for Elgamal encryption over the BLS12-381 curve, basically
/// a wrapper around the [`DecryptKey`] struct.
#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretKey {
    inner: DecryptKey<G1>,
}

impl SecretKey {
    /// Create a new secret key with group generator `g1` and secret `x`.
    pub fn new(g1: G1Affine, x: Fr) -> Self {
        Self {
            inner: DecryptKey::new(g1, x),
        }
    }

    /// Decrypt a ciphertext `ct` to get the message.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ark_std::UniformRand;
    /// use bls_elgamal::{Fr, SecretKey, G1Affine};
    /// use rand::prelude::StdRng;
    /// use rand_core::SeedableRng;
    ///
    /// let mut rng = StdRng::from_entropy();
    /// let x = Fr::rand(&mut rng);
    /// let g1 = G1Affine::rand(&mut rng);
    /// let m = G1Affine::rand(&mut rng);
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
    pub fn decrypt(&self, ct: Ciphertext<G1>) -> G1Affine {
        self.inner.decrypt(ct)
    }

    /// Get the public key from the secret key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.encrypt_key,
        }
    }
}

/// A public key for Elgamal encryption over the BLS12-381 curve, basically
/// a wrapper around the [`EncryptKey`] struct.
///
/// The public key is created from the secret key [`SecretKey`].
#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    inner: EncryptKey<G1>,
}

impl PublicKey {
    /// Encrypt a message `m` with randomness `r` to get a ciphertext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ark_std::UniformRand;
    /// use bls_elgamal::{Fr, SecretKey, G1Affine};
    /// use rand::prelude::StdRng;
    /// use rand_core::SeedableRng;
    ///
    /// let mut rng = StdRng::from_entropy();
    /// let x = Fr::rand(&mut rng);
    /// let g1 = G1Affine::rand(&mut rng);
    ///
    /// let sk = SecretKey::new(g1, x);
    /// let pk = sk.public_key();
    ///
    /// let m = G1Affine::rand(&mut rng);
    /// let r = Fr::rand(&mut rng);
    ///
    /// let ct = pk.encrypt(m, r);
    /// ```
    pub fn encrypt(&self, m: G1Affine, r: Fr) -> Ciphertext<G1> {
        self.inner.encrypt(m, r)
    }

    /// Rerandomize a ciphertext `ct` with randomness `r`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ark_std::UniformRand;
    /// use bls_elgamal::{Fr, SecretKey, G1Affine};
    /// use rand::prelude::StdRng;
    /// use rand_core::SeedableRng;
    ///
    /// let mut rng = StdRng::from_entropy();
    /// let x = Fr::rand(&mut rng);
    /// let g1 = G1Affine::rand(&mut rng);
    ///
    /// let sk = SecretKey::new(g1, x);
    /// let pk = sk.public_key();
    ///
    /// let m = G1Affine::rand(&mut rng);
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
