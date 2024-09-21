use std::ops::{Add, Mul, Sub};

use super::ciphertext::Ciphertext;

/// A key to encrypt a message. The encryption key is implemented with elliptic curve
/// cryptography, where S is the scalar field and P is the elliptic curve point.
///
/// The encryption key should be created from the secret key [`DecryptKey`].
#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) struct EncryptKey<S, P>
where
    P: Copy + Clone + Add<Output = P>,
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
    P: Copy + Clone + Add<Output = P>,
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
    P: Copy + Clone + Add<Output = P> + Mul<S, Output = P> + Sub<Output = P>,
    for<'a> P: Mul<&'a S, Output = P>,
{
    pub(crate) generator: P,
    pub(crate) secret: S, // x
    pub(crate) encrypt_key: EncryptKey<S, P>,
}

impl<S, P> DecryptKey<S, P>
where
    P: Copy + Clone + Add<Output = P> + Mul<S, Output = P> + Sub<Output = P>,
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
